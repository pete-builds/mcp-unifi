---
draft: false
title: Authentication
description: Bearer-token auth on the streamable-HTTP transport — setup, client config, audit log.
---

Starting in **v0.9.0**, the HTTP transport authenticates every incoming MCP request with an `Authorization: Bearer <token>` header. The server is **secure by default**: it refuses to start over `streamable-http` without tokens configured. Stdio transport is unaffected — the parent process owns the security boundary there, so adding bearer auth would be theatre.

## Why this changed

mcp-unifi exposes 57 Network tools, 11 Protect tools, and 18 Access tools. Many in Network and Protect are destructive: delete a VLAN, rewrite a firewall rule, disable Threat Management, block a client, change a camera's recording mode. Before v0.9.0 the server trusted the LAN, which meant a single compromised IoT device on the same network had admin-equivalent access to the controller. v0.9.0 closes that gap. Access is read-only in v0.10, but the same bearer-token gate still applies to it.

## Generate a token

```bash
openssl rand -hex 32
```

Use one token per client (Claude Code, n8n, Home Assistant, etc.) so you can revoke one without rotating all.

## Configure the server

Set `MCP_UNIFI_AUTH_TOKENS` as a comma-separated list. Each entry is either:

- a **bare token** (auto-assigned client_id `client-0`, `client-1`, ...)
- a **`name:token` pair** for named clients (recommended — the name shows up in the audit log)

```env
MCP_UNIFI_AUTH_TOKENS=claude:7f3a...,n8n:c812...,homeassistant:a4d9...
MCP_UNIFI_AUTH_REQUIRED=true
```

On boot, the server logs the configured client_ids (never the tokens) and starts. Without tokens and with `MCP_UNIFI_AUTH_REQUIRED=true`, the server raises at startup with a clear error.

## Configure the client

### Claude Code

Add the `Authorization` header in your MCP server config:

```json
{
  "mcpServers": {
    "unifi": {
      "type": "http",
      "url": "http://nix1:3714/mcp",
      "headers": {
        "Authorization": "Bearer 7f3a..."
      }
    }
  }
}
```

### Generic HTTP client

Every request to `/mcp` must carry:

```
Authorization: Bearer <token>
```

Missing or wrong → 401.

## Opting out (single-host trusted boundary only)

If the server is bound to `127.0.0.1` and only reachable from the same host inside a private network namespace, you can disable auth:

```env
MCP_UNIFI_AUTH_REQUIRED=false
```

The server boots with a loud `WARNING` log line every time. **Don't do this on a multi-host LAN, a tailnet, or anywhere a guest network could reach the port.**

## Audit log

Every tool call records the authenticated `client_id` in the JSONL audit log:

```json
{
  "ts": "2026-05-27T18:42:11.000Z",
  "controller": "default",
  "tool": "delete_firewall_rule",
  "client_id": "n8n",
  "args": {...},
  "success": true,
  "latency_ms": 142.3
}
```

`client_id` is `null` on stdio or when auth is disabled. Older entries from v0.8.0 and earlier omit the field entirely; replay tooling tolerates both shapes (no schema version bump — the field defaults to `null` when missing).

## What's still out of scope

- **Per-tool scopes**: every authenticated client can call every tool. Per-client RBAC is a v1.x decision.
- **Token rotation API**: rotate by editing the env var and restarting. No live rotation endpoint.
- **OAuth flows**: out of scope. The static-token model fits homelab single-admin use; if you need OAuth, front mcp-unifi with an authenticating reverse proxy (Authelia, Caddy + auth_request, etc.) and keep `MCP_UNIFI_AUTH_REQUIRED=false`.
- **Rate limiting**: not implemented.
