---
draft: false
title: Dry-Run & Audit Log
description: Preview destructive operations before applying them, and capture every call to a replayable JSONL log.
---

mcp-unifi's two safety primitives are **dry-run** (preview a destructive op without applying it) and the **audit log** (a JSONL record of every tool call, with secrets scrubbed). Together they give you a "look before you leap, then check what just happened" loop that other UniFi MCP servers don't have.

## Dry-run

Every destructive tool accepts `dry_run: bool = False`. When `True`, the tool computes the change it *would* apply, returns it as JSON, and does not write to the controller.

There are 30 dry-run-aware tools across the Network module and 5 in the Protect module. Read-only tools (list, get, observability, audit) don't need dry-run; they never write.

### Example: `create_vlan(dry_run=True)`

```json
{
  "dry_run": true,
  "controller": "default",
  "would_create": {
    "name": "iot",
    "vlan": 50,
    "ip_subnet": "10.50.0.0/24",
    "purpose": "corporate",
    "dhcpd_enabled": true,
    "dhcpd_start": "10.50.0.100",
    "dhcpd_stop": "10.50.0.200"
  },
  "summary": "Would create VLAN 'iot' (id=50, subnet=10.50.0.0/24) on controller 'default'"
}
```

Re-issue the call with `dry_run=False` (or omit it) to apply.

### Composite dry-runs

Composites like `create_iot_network` and `provision_homelab_service` return the full multi-step preview with placeholder IDs:

```json
{
  "dry_run": true,
  "controller": "default",
  "would_create": {
    "network": { "name": "iot", "vlan": 50, "..." },
    "wlan":    { "name": "iot-wifi", "network_id": "<dry-run-network-id>", "..." },
    "rule":    { "name": "Block iot to LAN", "src_networkconf_id": "<dry-run-network-id>", "..." }
  },
  "summary": "Would create IoT network + SSID + isolation rule on controller 'default'"
}
```

Composites guarantee that real applies (with `dry_run=False`) **roll back on partial failure**. If step 2 fails, step 1 is undone before the error returns. The response includes `partial` and `rolled_back` keys describing exactly what was undone.

## Audit log

Every tool call lands in a JSONL audit log. One line per call, regardless of success or failure. The audit decorator wraps tool registration so every tool body is captured uniformly.

### Record shape

```json
{
  "ts": "2026-05-15T13:42:07.123Z",
  "tool": "create_vlan",
  "controller": "default",
  "args": {
    "name": "iot",
    "vlan_id": 50,
    "subnet": "10.50.0.0/24"
  },
  "success": true,
  "latency_ms": 87,
  "stub_mode": false,
  "dry_run": false,
  "result_shape": { "kind": "ok", "ids": ["65f..."] }
}
```

Field notes:

- **`ts`**: UTC, ISO 8601 with milliseconds.
- **`args`**: any field name containing `passphrase`, `api_key`, `x_passphrase`, `password`, or `secret` is replaced with `"<scrubbed>"` before emission. The original kwargs are never written to the log.
- **`latency_ms`**: end-to-end tool latency including controller round-trip in real mode.
- **`result_shape`**: structured summary (success/error kind, returned IDs) — not the full response body.

### Configure the sink

| Env var | Default | What it does |
|---|---|---|
| `MCP_UNIFI_AUDIT_SINK` | `file` | One of `file`, `stdout`, `syslog`. |
| `MCP_UNIFI_AUDIT_PATH` | `audit.jsonl` | File path when `SINK=file`. |
| `MCP_UNIFI_AUDIT_SYSLOG_ADDRESS` | `/dev/log` | Socket path or `host:port` when `SINK=syslog`. |

## Replay

The package ships an `mcp-unifi-replay` console script that re-issues calls from a JSONL log. Useful for:

- **Migrations**: capture an audit from controller A, replay against controller B to converge state.
- **Reproducing test scenarios**: capture a buggy session locally, replay it in CI against the stub backend.
- **Disaster recovery drill**: confirm that a saved audit can rebuild your config end-to-end.

```bash
# Replay every call in the log against the configured controllers
mcp-unifi-replay audit.jsonl

# Filter to one tool
mcp-unifi-replay audit.jsonl --tool create_vlan

# Replay against a specific controller (overrides the per-call value)
mcp-unifi-replay audit.jsonl --controller home
```

Replay skips entries with `success: false` by default and honors `dry_run` exactly as captured. Pass `--apply` to force `dry_run=False` on replay (useful when the original capture was a planning session).

## Why this matters

The design assumption: the LLM **will** propose changes that need a second look, and you **will** want a forensic trail when something goes sideways at 11 pm. Dry-run lets the model and the human cooperate on a preview before any mutation. The audit log makes "what did Claude touch?" a one-grep question, and `mcp-unifi-replay` makes those captures executable against any controller.
