---
draft: false
title: Configuration
description: Full env var reference for mcp-unifi.
---

All configuration is read from environment variables (and a `.env` file when present). Pydantic validates values at startup; invalid config fails fast with a clear message.

## Mode toggle

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `STUB_MODE` | bool | `true` | no | When `false`, real-mode controller config is required (either legacy env vars or `MCP_UNIFI_CONTROLLERS_FILE`). |

## Legacy single-controller (auto-promoted)

These env vars cover the single-controller case. When set without `MCP_UNIFI_CONTROLLERS_FILE`, they auto-promote to a one-entry controller list named `default`. v0.4.x users keep working unchanged.

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `UNIFI_HOST` | string | `""` | real mode | Gateway IP or hostname (no scheme). |
| `UNIFI_API_KEY` | string | `""` | real mode | Local API key from **Settings → Control Plane → Integrations**. |
| `UNIFI_PORT` | int (1-65535) | `443` | no | HTTPS port for the gateway. |
| `UNIFI_SITE` | string | `default` | no | Controller site identifier. Most setups have one site. |
| `UNIFI_VERIFY_SSL` | bool | `false` | no | Set `true` once the gateway has a real TLS certificate. |

## Multi-controller

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `MCP_UNIFI_CONTROLLERS_FILE` | path | (unset) | no | YAML file listing named controllers. When set, the legacy `UNIFI_*` vars are ignored. See the [Multi-Site Setup guide](/mcp-unifi/guides/multi-site/) for the schema. |

## Module dispatcher

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `MCP_UNIFI_MODULES_ENABLED` | CSV string | `network` | no | Modules to load. Known values: `network`, `protect`, `access`. Unknown values fail startup with `UnknownModuleError`. Access requires `UNIFI_ACCESS_HOST` and `UNIFI_ACCESS_API_KEY` in real mode. |

## Access module (opt-in)

Only required when `MCP_UNIFI_MODULES_ENABLED` includes `access` and `STUB_MODE=false`. See the [Access setup guide](/mcp-unifi/guides/access-setup/).

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `UNIFI_ACCESS_HOST` | string | `""` | access + real mode | Access hub IP or hostname. Often the same as `UNIFI_HOST`. |
| `UNIFI_ACCESS_API_KEY` | string | `""` | access + real mode | Access API key. Separate from the Network API key; generated on the Access controller's developer settings. |
| `UNIFI_ACCESS_PORT` | int (1-65535) | `12445` | no | HTTPS port for the Access hub (the direct Access app port). |

## Transport

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `MCP_TRANSPORT` | enum (`stdio`, `streamable-http`) | `streamable-http` | no | `stdio` for Claude Desktop / `uvx` / `.dxt` installs; `streamable-http` for the long-running container. |
| `MCP_HOST` | string | `0.0.0.0` | no | Bind address (Streamable HTTP only). |
| `MCP_PORT` | int (1-65535) | `3714` | no | Listen port (Streamable HTTP only). |

## HTTP authentication

The Streamable HTTP transport is secure by default. See the [Authentication guide](/mcp-unifi/guides/auth/) for the full model.

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `MCP_UNIFI_AUTH_REQUIRED` | bool | `true` | no | When `true`, the HTTP transport refuses to start without tokens. Set to `false` only on a loopback-bound single-host deployment. Stdio transport ignores this. |
| `MCP_UNIFI_AUTH_TOKENS` | CSV string | `""` | HTTP + auth on | Comma-separated bearer tokens. Each entry is one of: a bare token (auto-assigned `client-N`), a `name:token` pair (recommended — name shows up in the audit log), or a `name:token:module1\|module2` triple to scope a client to specific modules. Pipe-separated because comma is the entry delimiter. Known modules: `network`, `protect`, `access`; `*` means all. |

## Logging

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `LOG_LEVEL` | enum | `INFO` | no | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `LOG_FORMAT` | enum (`json`, `text`) | `json` | no | `json` for production, `text` for local dev. Logs go to stderr (stdout is reserved for stdio JSON-RPC framing). |

## Audit log

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `MCP_UNIFI_AUDIT_SINK` | enum | `file` | no | One of `file`, `stdout`, `syslog`. |
| `MCP_UNIFI_AUDIT_PATH` | path | `audit.jsonl` | no | File path when `SINK=file`. Relative paths resolve from the process CWD. |
| `MCP_UNIFI_AUDIT_SYSLOG_ADDRESS` | string | `/dev/log` | no | Socket path or `host:port` when `SINK=syslog`. |

See the [Dry-Run & Audit Log guide](/mcp-unifi/guides/dry-run-audit/) for the JSONL record schema and `mcp-unifi-replay` usage.

## IoT defaults

These shape the subnet and DHCP range that `create_iot_network` synthesizes when callers don't specify them.

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `IOT_SUBNET_TEMPLATE` | string | `10.0.{vlan_id}.0/24` | no | Subnet template. Must contain the literal `{vlan_id}` placeholder. |
| `IOT_DHCP_START_OFFSET` | int (2-254) | `100` | no | First DHCP lease offset within the IoT /24. |
| `IOT_DHCP_STOP_OFFSET` | int (2-254) | `200` | no | Last DHCP lease offset. Must be greater than `IOT_DHCP_START_OFFSET`. |

## Validation behavior

- Pydantic validates types and ranges at startup.
- Invalid values fail with a clear message that names the field.
- Real mode with no controller config (no `MCP_UNIFI_CONTROLLERS_FILE`, no legacy `UNIFI_HOST` + `UNIFI_API_KEY`) is a hard error.
- Duplicate controller names in the YAML are rejected.
- `IOT_DHCP_STOP_OFFSET <= IOT_DHCP_START_OFFSET` is rejected.
- `IOT_SUBNET_TEMPLATE` without the `{vlan_id}` placeholder is rejected.

## `.env` file

The server reads `.env` from the process CWD if present. Values in the actual environment override `.env`. The repo's `.env.example` is a good starting template.

## Inspecting the resolved config

On startup, the server logs a `safe_repr()` of its resolved config. Per-controller `api_key` values are never included; each controller gets an `api_key_set: true/false` boolean instead. Grep startup logs for `safe_repr` to confirm what the server actually loaded.
