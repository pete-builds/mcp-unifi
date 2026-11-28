---
draft: false
title: Dry-Run & Audit Log
description: Preview destructive operations before applying them, and capture every call to a replayable JSONL log.
---

mcp-unifi's two safety primitives are **dry-run** (preview a destructive op without applying it) and the **audit log** (a JSONL record of every tool call, with secrets scrubbed). Together they give you a "look before you leap, then check what just happened" loop that other UniFi MCP servers don't have.

## Dry-run

Tools that change controller state accept `dry_run: bool = False`. When `True`, the tool computes the change it *would* apply, returns it as JSON, and does not write to the controller. Two state-changing tools take no `dry_run`: `trigger_speedtest`, which starts a speed test rather than editing configuration, and `confirm_destructive_action`, which applies a delete you already previewed. Read-only tools (list, get, observability, audit) don't need dry-run; they never write.

### Example: `create_vlan(dry_run=True)`

```json
{
  "dry_run": true,
  "controller": "default",
  "would_create": {
    "network": {
      "name": "iot",
      "purpose": "corporate",
      "vlan_enabled": true,
      "vlan": 50,
      "ip_subnet": "10.50.0.1/24",
      "dhcpd_enabled": true,
      "dhcpd_start": "10.50.0.100",
      "dhcpd_stop": "10.50.0.200",
      "enabled": true
    }
  },
  "summary": "Would create VLAN 'iot' (id=50) on 10.50.0.0/24"
}
```

That is the response to `create_vlan(name="iot", vlan_id=50, subnet="10.50.0.0/24", dry_run=True)` from the in-memory stub. Re-issue the call with `dry_run=False` (or omit it) to apply.

### Composite dry-runs

Composites like `create_iot_network` and `provision_homelab_service` return the full multi-step preview with placeholder IDs. This is the response to `create_iot_network(name="iot", vlan_id=50, passphrase="hunter2hunter2", dry_run=True)` from the stub; the passphrase comes back as `[REDACTED]`:

```json
{
  "dry_run": true,
  "controller": "default",
  "would_create": {
    "network": {
      "name": "iot",
      "purpose": "corporate",
      "vlan_enabled": true,
      "vlan": 50,
      "ip_subnet": "10.0.50.1/24",
      "dhcpd_enabled": true,
      "dhcpd_start": "10.0.50.100",
      "dhcpd_stop": "10.0.50.200",
      "enabled": true
    },
    "wlan": {
      "name": "iot",
      "enabled": true,
      "security": "wpapsk",
      "wpa_mode": "wpa2",
      "x_passphrase": "[REDACTED]",
      "networkconf_id": "<dry-run-network-id>",
      "is_guest": false,
      "hide_ssid": false,
      "wlan_band": "both",
      "ap_group_ids": ["<auto-resolve-default>"],
      "ap_group_mode": "all"
    },
    "firewall_rule": {
      "name": "Block iot -> Main LAN",
      "ruleset": "LAN_IN",
      "rule_index": 20050,
      "action": "drop",
      "protocol": "all",
      "enabled": true,
      "src_address": "10.0.50.0/24",
      "dst_address": "192.168.1.0/24"
    }
  },
  "summary": "Would create IoT network 'iot' (VLAN 50) on 10.0.50.1/24, SSID, and isolation rule",
  "note": "WLAN.networkconf_id and downstream IDs are placeholders; the real apply substitutes the controller-assigned _id."
}
```

On a site that uses the Zone-Based Firewall, the isolation step creates a zone policy instead of a legacy `firewall_rule`. Composites roll back on partial failure. If a later step fails on a real apply (`dry_run=False`), the steps that already succeeded are undone before the error returns, and the error response carries `partial` (what the controller had already created, secrets redacted) and `rolled_back` (what was undone).

## Audit log

Every tool call lands in a JSONL audit log. One line per call, regardless of success or failure. The audit decorator wraps tool registration so every tool body is captured uniformly.

### Record shape

This is the record the stub wrote for `create_vlan(name="iot", vlan_id=50, subnet="10.50.0.0/24", dry_run=True)`. The file holds each record on a single line with the keys sorted alphabetically; it is pretty-printed here:

```json
{
  "args": {
    "controller": "default",
    "dhcp_start": "",
    "dhcp_stop": "",
    "dry_run": true,
    "name": "iot",
    "purpose": "corporate",
    "subnet": "10.50.0.0/24",
    "vlan_id": 50
  },
  "chain_start": "new_log",
  "client_id": null,
  "controller": "default",
  "denied_by": null,
  "error": null,
  "event_id": "86ce43c936484327bb7c0c150a9edff7",
  "hash": "05c9fddbcaa98ad229a6b6fdba469623b13f4cddbc791f6c08f083f5cc04af44",
  "latency_ms": 0.06,
  "operation_id": "86ce43c936484327bb7c0c150a9edff7",
  "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "result": {
    "controller": "default",
    "dry_run": true,
    "summary": "Would create VLAN 'iot' (id=50) on 10.50.0.0/24",
    "would_create": {
      "network": {
        "dhcpd_enabled": true,
        "dhcpd_start": "10.50.0.100",
        "dhcpd_stop": "10.50.0.200",
        "enabled": true,
        "ip_subnet": "10.50.0.1/24",
        "name": "iot",
        "purpose": "corporate",
        "vlan": 50,
        "vlan_enabled": true
      }
    }
  },
  "schema": "2",
  "success": true,
  "tool": "create_vlan",
  "ts": "2026-11-27T23:26:34.019Z"
}
```

Field notes:

- **`ts`**: UTC, ISO 8601 with milliseconds and a `Z` suffix.
- **`tool`**, **`controller`**: the tool the caller invoked and the controller it targeted (`default` when the call named none).
- **`args`**: every argument the tool received, including defaults the caller did not set. Any key matching one of the sensitive-key patterns (`SENSITIVE_KEY_PATTERNS` in `mcp_unifi/redaction.py`: for example `passphrase`, `password`, `secret`, `token`, `api_key`) has its value replaced with `"***"` before the record is written. The patterns match as case-insensitive substrings of the key.
- **`result`**: the tool's response, parsed back into JSON and scrubbed the same way, so a WLAN `x_passphrase` in a response is also `"***"`. It is `null` when the tool raised or the call was refused. The scrub marker in the log is `"***"`; tool responses sent to the client use `"[REDACTED]"` instead.
- **`success`**: `true` when the tool body returned, `false` when it raised or the call was refused. A tool that returns an error envelope, which is how a controller rejection usually surfaces, is recorded with `success: true`. Read `result` for the outcome.
- **`error`**: the exception text when the tool raised, or the refusal message for a refused call. Otherwise `null`.
- **`latency_ms`**: wall-clock milliseconds around the tool body, including the controller round-trip in real mode. `0.0` for a refused call, because nothing ran.
- **`client_id`**: the authenticated client on the HTTP transport. `null` on stdio or when auth is off.
- **`denied_by`**: which control refused the call before it reached the tool, or `null` (see below).
- **`event_id`**: a unique id for this record (32 hex characters).
- **`operation_id`**: groups the records that make up one change. For an ordinary call it equals the record's own `event_id`. A destructive preview and the `confirm_destructive_action` that executes it share one: the preview's `event_id`. See [Follow one change](#follow-one-change).
- **`prev_hash`**, **`hash`**: the hash chain. `hash` is SHA-256 over the record without `hash`, and `prev_hash` is the `hash` of the record before it. See [Check the log for tampering](#check-the-log-for-tampering).
- **`chain_start`**: set only on a record that begins a new chain segment, naming why (`new_log`, `after_unchained`, `after_unreadable`, `process_start`). `null` everywhere else.
- **`schema`**: the record format version, currently `"2"`. Version 2 added the five fields above. Records written by older versions say `"1"` and lack them; everything that reads the log still accepts them.

Here is what the scrub does to a secret. The stub wrote this for `create_wlan(..., passphrase="hunter2hunter2", dry_run=True)`; the remaining fields are omitted:

```json
{
  "args": { "name": "iot-wifi", "passphrase": "***" },
  "result": { "would_create": { "wlan": { "name": "iot-wifi", "x_passphrase": "***" } } }
}
```

### Refused calls

A call that a control turned away never reaches a tool body, so it would otherwise leave no trace in the log at all. Those attempts are recorded too, with a `denied_by` field naming the control that refused them:

| `denied_by` | Refused by | Fix if it was legitimate |
|---|---|---|
| `"readonly"` | The read-only write gate (`MCP_UNIFI_READONLY=true`) | Turn the posture off, or run the change by hand. |
| `"scope"` | Per-client module scoping (`MCP_UNIFI_AUTH_TOKENS`) | Widen that client's module allowlist. |
| `null` | Nothing — the call was dispatched | n/a |

```bash
# What did my agent try to do that it was not allowed to do?
jq -c 'select(.denied_by) | {ts, client_id, tool, denied_by}' audit.jsonl
```

Refused records carry `success: false`, `result: null`, `latency_ms: 0.0` and the refusal message in `error`, and their `args` are scrubbed on exactly the same path as a dispatched call: a refused `create_wlan` does not write the passphrase the caller supplied.

Don't key off `success` alone: it is also `false` when a tool raised, and when the call was cancelled before the tool returned. A cancelled call is recorded with an `error` saying the outcome at the controller is unknown, because the request may or may not have reached it: check the controller before retrying a write. `denied_by` is the only field that distinguishes "the call was never made" from "the call was made and failed". `mcp-unifi-replay` reads it too, and skips refused events rather than re-issuing them.

### Follow one change

A destructive tool (`delete_vlan`, `restore_config` and the rest) only previews. The change happens later, when the caller passes the token to `confirm_destructive_action`. Both halves are recorded, and both carry the same `operation_id`, so one filter returns the whole story of a change, in order:

```bash
# Every record that belongs to the change that preview started
jq -c --arg op 9078cdafcb7a4398897e45323ae1f041 \
  'select(.operation_id == $op) | {ts, tool, event_id, success}' audit.jsonl
```

```json
{"ts":"2026-11-27T23:26:34.021Z","tool":"delete_vlan","event_id":"9078cdafcb7a4398897e45323ae1f041","success":true}
{"ts":"2026-11-27T23:26:34.023Z","tool":"confirm_destructive_action","event_id":"156a32c017f64e68af8181f65e7b5d98","success":true}
```

The link is kept by the server alongside the pending action, never inside the token, and the ids are not added to any tool's response. A confirm with an unknown, expired or someone else's token executes nothing and is recorded as an operation of its own. A confirm refused by read-only mode or by client scoping is refused before the server looks at the token, so it is not linked to the preview either.

### Configure the sink

| Env var | Default | What it does |
|---|---|---|
| `MCP_UNIFI_AUDIT_SINK` | `file` | One of `file`, `stdout`, `syslog`. |
| `MCP_UNIFI_AUDIT_PATH` | `audit.jsonl` | File path when `SINK=file`. |
| `MCP_UNIFI_AUDIT_SYSLOG_ADDRESS` | `/dev/log` | Socket path or `host:port` when `SINK=syslog`. |

The sink is checked when the server starts, not on the first tool call:

- An unknown `MCP_UNIFI_AUDIT_SINK` value (a typo such as `files`) stops startup with a message naming the valid values.
- `MCP_UNIFI_AUDIT_SINK=stdout` together with `MCP_TRANSPORT=stdio` stops startup. The stdio transport owns stdout for its JSON-RPC stream, and audit lines written there would corrupt it. Use `file` or `syslog` for a stdio server.
- A `file` sink whose path cannot be written does **not** stop startup, because tool calls still work. The server logs one ERROR naming the path and the fix, and `/health` reports it: `"audit": {"sink": "file", "writable": false}`. If you see that, nothing is being recorded. The usual cause is the default `audit.jsonl` on a read-only root filesystem; set the sink to `stdout` or point `MCP_UNIFI_AUDIT_PATH` at a mounted volume.

## Check the log for tampering

Each record carries the hash of the record before it, so the records form a chain. `mcp-unifi-audit-verify` walks the file and reports the first place the chain does not hold.

**What it detects:** within one segment, an edited, removed, reordered or inserted record is detected, unless whoever changed the file also recomputed the hashes.

**What it does not detect:** records removed from the end of a segment or the end of the file; a removed, duplicated or reordered whole segment or whole rotated file; a full rewrite.

A *segment* is a run of records chained one to the next. A new one starts on a fresh log, after an upgrade, after a crash mid-write, when the server restarts after a log was rotated, and at every process start on a stdout or syslog sink.

```bash
mcp-unifi-audit-verify audit.jsonl
```

```text
audit-verify: OK audit.jsonl
  records: 5
  chained records: 5
  segments: 1
    1. starts at audit.jsonl:1 (new_log)
  last record hash: b146de1978f2872e91be9b8f3f1ee1074efabdafe49665f879ee7a54da5d53ac (audit.jsonl:5)
  not covered: records before a segment start or after the last record, a removed, duplicated or reordered whole segment or rotated file, and a full rewrite of the file
```

With a record removed from the middle:

```text
audit-verify: BROKEN at audit.jsonl:4
  reason: a record is missing: the record this one follows is not in the input (deleted, or a write was lost)
  verified through: audit.jsonl:3
```

Every report lists where each segment starts and the last record's hash. Both are information about the file, not a promise: nothing in the file can show that records before a segment start, or after the last record, were not removed.

Exit status:

| Code | Meaning |
|---|---|
| `0` | Verified. |
| `1` | A break. The output names the first one. |
| `2` | Usage error, or a file cannot be read. |
| `3` | Verified, with warnings: damaged lines, or a segment the server started without being able to read its log (see below). |

**Running it from cron:** exit `3` means the chain verified but the log has damaged lines or an unreadable restart where records may be missing. Treat it as needing a look, not as a pass and not as proof of tampering.

`--json` prints one object instead (`ok`, `break`, `segments`, `damaged_lines`, `unvouched_segment_starts`, `head_hash` and counts). Pass several files to check a rotated log as one chain, oldest first: `mcp-unifi-audit-verify audit.jsonl.1 audit.jsonl`.

### The limits, plainly

- **Anyone who can write the file can rewrite it.** SHA-256 is not a secret: an edit followed by recomputing every hash after it verifies. This is tamper evidence against edits that do not recompute the chain, not a signature.
- **Records cut off the end of the file** leave a shorter chain that still verifies. So do records cut off the end of any segment, just before the next segment starts.
- **A whole segment can go missing, be duplicated or be moved unnoticed**: a whole process run on a stdout or syslog sink dropped, repeated or swapped with another, or the same file passed to the verifier twice.
- **Dropping a whole rotated file from the middle of a set is not detected** whenever the next file starts a new segment, which it does if the server restarted after rotating. Do not rely on the verifier to tell you a rotated file is missing.
- **A file rotated while the server kept running** (logrotate's `copytruncate`) starts in the middle of a chain. On its own it reports a break at its first line; verify it together with the file before it, oldest first.

### Damaged lines

If the server crashes partway through writing a record, the file ends in a cut-off line. When it next writes, it starts on a fresh line and begins a new segment marked `chain_start: "after_unreadable"`. The verifier reports each cut-off line (two in a row if it crashed again before finishing that first record), verifies everything after it, and exits `3`. The same holds when the cut-off line is the last line of its file: the server has not written since the crash, or the file was rotated before it did (the next file then starts with `new_log`).

```text
audit-verify: DAMAGED audit.jsonl (verified, with damaged lines; see below)
  WARNING: damaged line at audit.jsonl:4 (crash mid-write?): not a record; an unknown number of records at this point may be missing
  records: 4
  chained records: 4
  damaged lines: 1
  segments: 2
    1. starts at audit.jsonl:1 (new_log)
    2. starts at audit.jsonl:5 (after_unreadable)
```

An unknown number of records may be missing at a damaged line, not just the one that was being written: anyone who replaced the end of the file with a line of garbage and then let the server restart produces exactly this picture. Treat exit `3` as "look at this", not as a pass.

A line that is not JSON followed by anything other than a restart in the same file, any line that is JSON but not a valid record, and an `after_unreadable` record that does not directly follow such damage in the same file are all breaks.

### Failed writes and concurrent writers

**A failed write usually shows up as a missing record.** If the sink fails to write a record that was already hashed (a full disk, say), the next record still points at it, so the verifier reports a missing record at that spot. The server logged an ERROR for the failed write when it happened, so check the server log before treating it as tampering. If a record could not even be serialised, it is never hashed, nothing is written, and the chain carries on without a gap: the only trace is the ERROR in the server log.

**One writer per file.** The server keeps the newest hash in memory and reads the file only once, when it first writes after starting. Two processes appending to one file fork the chain, and the verifier reports the first record where they cross. That includes `mcp-unifi-replay --real` while the server is running and both use the same file sink.

**A server that can append to its log but not read it** (a file with mode `0200`, say) still writes every record. It cannot see what came before, so it starts a segment marked `chain_start: "unreadable_log"` (and, not knowing whether the file ends in a newline, writes one first, which may leave a blank line every reader skips). The verifier accepts that segment start anywhere, warns that an unknown number of records before it may be missing, and exits `3`. A file sink pointed at something that is not a regular file, such as a piped `/dev/stdout`, is never read back; it starts a segment per process, like the stdout sink. A file the server cannot write at all records nothing, as before this change, and the server logs an ERROR for each record.

### Upgrading an existing log

Nothing is rewritten. On its first write after the upgrade the server reads the last line of the existing file. Because that line predates the chain, it starts a new segment: the first new record has `prev_hash` set to sixty-four zeros and `chain_start: "after_unchained"`. The verifier reports the old records as unchained, which is not a break:

```text
audit-verify: OK audit.jsonl
  records: 4
  chained records: 2
  unchained records (written before the chain existed): 2 (audit.jsonl:1 to audit.jsonl:2)
  segments: 1
    1. starts at audit.jsonl:3 (after_unchained)
```

Unchained records carry no protection, and they are accepted only *before* the first chained record of a file. An unchained record after a chained one is a break: either someone stripped the hash fields from a record, or the server was downgraded to a version without the chain, and the verifier cannot tell which. Running an older version against a chained log breaks verification from that point on, so rotate the file before downgrading.

A missing or empty file starts at `chain_start: "new_log"`, which is valid only as the first record of a file. A file that ends without a final newline gets one before the server's first new record. When the server restarts after a log was rotated, the new file starts with `new_log` too, and verifying the old and new files together lists it as a second segment.

### stdout and syslog sinks

The chain is kept per process for every sink. A process writing to `stdout` or `syslog` cannot read back what it wrote before it restarted, so each process start begins a new segment, marked `chain_start: "process_start"`. To verify, collect the audit lines into a file with nothing else on them (for example `docker logs <container> 2>/dev/null > audit.jsonl`; strip any syslog prefix so each line is the JSON record alone) and run the verifier on it.

The same guarantee applies inside each process's run as your collector stored it, and the same limits: records lost at the end of a run, or a whole run, are not detected. Nothing in the log can show that a `process_start` really was a restart, so on these sinks segment boundaries are taken on trust. A transport that drops lines (syslog over UDP) shows up as missing records.

## Replay

The package ships an `mcp-unifi-replay` console script that re-issues the calls in a JSONL log, in order, against a fresh in-process server. It is useful for reproducing a captured session: capture a buggy session locally, then replay it in CI against the stub backend. Replay does not go through the HTTP transport: it builds its own stdio-style server whatever `MCP_TRANSPORT` says, so it needs no bearer token and applies no per-client module scopes. Read-only mode (`MCP_UNIFI_READONLY=true`) still applies, because it is a posture of the whole server and not of one client. Treat replay as an operator tool (see the [Authentication guide](/mcp-unifi/guides/auth/)).

```bash
# Replay every event in the log against the in-memory stub (the default)
mcp-unifi-replay audit.jsonl

# The same, with one JSON result per event on stdout
mcp-unifi-replay audit.jsonl --json

# Real-mode replay needs all three flags
mcp-unifi-replay audit.jsonl --real --target-controller home --i-mean-it
```

The flags, from `mcp-unifi-replay --help`:

| Flag | Meaning |
|---|---|
| `log_path` | Path to the audit log (JSONL, one event per line). Required. |
| `--real` | Replay against a real controller instead of the stub. Requires `--target-controller` and `--i-mean-it`. |
| `--target-controller NAME` | Real mode only: the one controller allowed to receive replayed calls. Events whose `controller` field differs are skipped, not failed. |
| `--i-mean-it` | Real mode only: second confirmation. Without it, `--real` exits with status 2 before any call is made. |
| `--json` | Print one JSON object per event (`tool`, `controller`, `success`, `error`, `skipped`, `skip_reason`) instead of the summary line. |

Without `--json` the command prints `replay complete: N events (succeeded=…, failed=…, skipped=…)`. The exit status is `0` when nothing failed, `1` when at least one event failed, and `2` for a usage or log-file error. There is no flag to filter by tool, override the controller, or force `dry_run`: replay passes each event's recorded `args` to the tool as captured.

In real mode the server is built from the controllers your environment configures (see the [Configuration reference](/mcp-unifi/reference/configuration/)).

Three kinds of event are skipped, never re-issued, and each says why in `skip_reason`:

- **Refused calls.** An event recorded with a `denied_by` value was never made, and replaying it would take the action your own policy denied.
- **Calls for another controller**, in real mode: any event whose `controller` is not the `--target-controller`.
- **Calls whose arguments were redacted.** The log stores scrubbed arguments, so a WLAN passphrase is recorded as `***` and the real value is not in the log. Sending `***` would set the passphrase to those three characters and report success, so the call is skipped instead. Every `confirm_destructive_action` falls in this group, because its one-time token is redacted: a replay never re-confirms a delete.

A tool that answers with an error envelope counts as failed, not succeeded.

What a replay writes to the audit log depends on the mode:

- A **stub** replay is a rehearsal. It writes nothing to the configured audit sink, so a rehearsed call cannot be mistaken for a real one.
- A **real** replay is a real change and is audited like any other call, with `client_id` set to `mcp-unifi-replay` so you can tell replayed calls apart (`jq 'select(.client_id == "mcp-unifi-replay")'`). It refuses to start when the log you ask it to replay is the very file the audit sink appends to. Copy the log and replay the copy.

## Why this matters

The design assumption: the LLM **will** propose changes that need a second look, and you **will** want a forensic trail when something goes sideways at 11 pm. Dry-run lets the model and the human cooperate on a preview before any mutation. The audit log makes "what did Claude touch?" a one-grep question, and `mcp-unifi-replay` can re-run a capture against the stub.
