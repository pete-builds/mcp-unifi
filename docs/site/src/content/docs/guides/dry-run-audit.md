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
  "client_id": null,
  "controller": "default",
  "denied_by": null,
  "error": null,
  "latency_ms": 0.044,
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
  "schema": "1",
  "success": true,
  "tool": "create_vlan",
  "ts": "2026-11-10T23:59:45.420Z"
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
- **`schema`**: the record format version, currently `"1"`.

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

Don't key off `success` alone: it is also `false` when a tool raised. `denied_by` is the only field that distinguishes "the call was never made" from "the call was made and failed". `mcp-unifi-replay` reads it too, and skips refused events rather than re-issuing them.

### Configure the sink

| Env var | Default | What it does |
|---|---|---|
| `MCP_UNIFI_AUDIT_SINK` | `file` | One of `file`, `stdout`, `syslog`. |
| `MCP_UNIFI_AUDIT_PATH` | `audit.jsonl` | File path when `SINK=file`. |
| `MCP_UNIFI_AUDIT_SYSLOG_ADDRESS` | `/dev/log` | Socket path or `host:port` when `SINK=syslog`. |

## Replay

The package ships an `mcp-unifi-replay` console script that re-issues the calls in a JSONL log, in order, against a fresh in-process server. It is useful for reproducing a captured session: capture a buggy session locally, then replay it in CI against the stub backend. Replay does not go through the HTTP transport, so it runs without a bearer token and ignores per-client module scopes; treat it as an operator tool (see the [Authentication guide](/mcp-unifi/guides/auth/)).

```bash
# Replay every event in the log against the in-memory stub (the default)
MCP_TRANSPORT=stdio mcp-unifi-replay audit.jsonl

# The same, with one JSON result per event on stdout
MCP_TRANSPORT=stdio mcp-unifi-replay audit.jsonl --json

# Real-mode replay needs all three flags
MCP_TRANSPORT=stdio mcp-unifi-replay audit.jsonl --real --target-controller home --i-mean-it
```

The flags, from `mcp-unifi-replay --help`:

| Flag | Meaning |
|---|---|
| `log_path` | Path to the audit log (JSONL, one event per line). Required. |
| `--real` | Replay against a real controller instead of the stub. Requires `--target-controller` and `--i-mean-it`. |
| `--target-controller NAME` | Real mode only: the one controller allowed to receive replayed calls. Events whose `controller` field differs are skipped, not failed. |
| `--i-mean-it` | Real mode only: second confirmation. Without it, `--real` exits with status 2 before any call is made. |
| `--json` | Print one JSON object per event (`tool`, `controller`, `success`, `error`, `skipped`, `skip_reason`) instead of the summary line. |

Without `--json` the command prints `replay complete: N events (succeeded=…, failed=…, skipped=…)`. The exit status is `0` when nothing failed, `1` when at least one event failed, and `2` for a usage or log-file error. Events recorded with a `denied_by` value are skipped, never re-issued. There is no flag to filter by tool, override the controller, or force `dry_run`: replay passes each event's recorded `args` to the tool as captured.

`MCP_TRANSPORT=stdio` appears in every example because replay builds its server from the normal settings, whose default transport is Streamable HTTP and needs a bearer token; without it the command stops with `HTTP transport requires MCP_UNIFI_AUTH_TOKENS`. In real mode the server is built from the controllers your environment configures (see the [Configuration reference](/mcp-unifi/reference/configuration/)).

Because the log stores scrubbed arguments, a secret such as a WLAN passphrase is recorded as `***`; the log does not hold the real value.

## Why this matters

The design assumption: the LLM **will** propose changes that need a second look, and you **will** want a forensic trail when something goes sideways at 11 pm. Dry-run lets the model and the human cooperate on a preview before any mutation. The audit log makes "what did Claude touch?" a one-grep question, and `mcp-unifi-replay` can re-run a capture against the stub.
