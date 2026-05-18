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
| `MCP_UNIFI_MODULES_ENABLED` | CSV string | `network` | no | Modules to load. Known values: `network`, `protect`. Unknown values fail startup with `UnknownModuleError`. |

## Transport

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `MCP_TRANSPORT` | enum (`stdio`, `streamable-http`) | `streamable-http` | no | `stdio` for Claude Desktop / `uvx` / `.dxt` installs; `streamable-http` for the long-running container. |
| `MCP_HOST` | string | `0.0.0.0` | no | Bind address (Streamable HTTP only). |
| `MCP_PORT` | int (1-65535) | `3714` | no | Listen port (Streamable HTTP only). |

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
