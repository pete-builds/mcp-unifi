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

Each record carries the hash of the record before it, so the records form a chain. `mcp-unifi-audit-verify` walks the file and reports the first place the chain does not hold:

```bash
mcp-unifi-audit-verify audit.jsonl
```

```text
audit-verify: OK audit.jsonl
  chained records: 5
  segment starts at audit.jsonl:1 (new_log)
  head: ac488cb54acf0d30829f706e18ad952470ec49c59f86f64a0deb7d4277b766e3 (audit.jsonl:5)
```

With a record removed from the middle:

```text
audit-verify: BROKEN at audit.jsonl:4
  reason: a record is missing: the record this one follows is not in the input (deleted, or a write was lost)
  verified through: audit.jsonl:3
  chained records: 3
  segment starts at audit.jsonl:1 (new_log)
  last verified hash: 012afdb5e8c90c12b807a1964dd17a7fccf701ac54548035ff7279398391474b (audit.jsonl:3)
```

The exit status is `0` when the chain holds, `1` at the first break, and `2` when a file cannot be read. `--json` prints one object instead (`ok`, `break`, `head_hash` and counts), so `mcp-unifi-audit-verify audit.jsonl --json | jq -r .head_hash` prints just the head. Pass several files to check a rotated log as one chain, oldest first: `mcp-unifi-audit-verify audit.jsonl.1 audit.jsonl`.

### What a pass proves, and what it does not

**It detects** a record that was edited, removed from the middle or the start, duplicated, or moved, by someone who did not recompute the chain. The verifier names the line and the kind of break.

**It does not stop** someone who can write to the file from rewriting the whole thing. SHA-256 is not a secret: anyone with write access can edit a record and recompute every hash after it, and the result verifies. The chain raises the cost of quiet tampering and catches careless or partial edits; it is not a signature.

**It cannot see records cut off the end of the file.** A file that lost its last ten records is still a valid chain, just a shorter one. The defence is to copy the `head` hash somewhere the server cannot write (a ticket, a chat message, a cron job that ships it to another host) and later check that the record carrying it is still in the file: `grep -c '"hash": "<head>"' audit.jsonl` should print `1`. This server does not do that for you.

**A failed write shows up as a missing record.** If the sink fails to write a record (a full disk, say), the next record still points at it, so the verifier reports a missing record at that spot. The server logged an ERROR for the failed write when it happened, so check the server log before treating it as tampering.

**One writer per file.** The server keeps the newest hash in memory and reads the file only once, when it first writes after starting. Two processes appending to one file fork the chain, and the verifier reports the first record where they cross. That includes `mcp-unifi-replay --real` while the server is running and both use the same file sink.

### Upgrading an existing log

Nothing is rewritten. On its first write after the upgrade the server reads the last line of the existing file. Because that line predates the chain, it starts a new segment: the first new record has `prev_hash` set to sixty-four zeros and `chain_start: "after_unchained"`. The verifier reports the old records as unchained, which is not a break:

```text
audit-verify: OK audit.jsonl
  chained records: 2
  unchained records (written before the chain existed): 2 (audit.jsonl:1 to audit.jsonl:2)
  segment starts at audit.jsonl:3 (after_unchained)
  head: 387b7b5a0e39a426b394c2e3898a4d1686d75680304dee9b8a7a19c40c6d093f (audit.jsonl:4)
```

Unchained records carry no protection. If the verifier notes unchained records *after* chained ones, either the server was downgraded to a version without the chain, or someone stripped the hash fields from the newest records; the verifier cannot tell which.

A missing or empty file starts at `chain_start: "new_log"`. A last line that cannot be read (a write cut off mid-line) starts a segment with `chain_start: "after_unreadable"`, and the verifier reports the damaged line itself as a break.

### stdout and syslog sinks

The chain is kept per process for every sink. A process writing to `stdout` or `syslog` cannot read back what it wrote before it restarted, so each process start begins a new segment, marked `chain_start: "process_start"`. To verify, collect the audit lines into a file with nothing else on them (for example `docker logs <container> 2>/dev/null > audit.jsonl`; strip any syslog prefix so each line is the JSON record alone) and run the verifier on it. A pass then means no record was edited, removed or reordered *within each process's run* as your collector stored it. It cannot tell you that a whole run is missing, and a transport that drops lines (syslog over UDP) shows up as missing records.

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
