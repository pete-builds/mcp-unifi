---
draft: false
title: Authentication
description: Bearer-token auth on the streamable-HTTP transport — setup, client config, audit log.
---

Starting in **v0.9.0**, the HTTP transport authenticates every incoming MCP request with an `Authorization: Bearer <token>` header. The server is **secure by default**: it refuses to start over `streamable-http` without tokens configured. Stdio transport is unaffected — the parent process owns the security boundary there, so adding bearer auth would be theatre.

## Why this changed

mcp-unifi exposes a large tool surface across Network, Protect, and Access (see the [Tool Manifest](/mcp-unifi/tools/) for the current per-module count). Many Network and Protect tools are destructive: delete a VLAN, rewrite a firewall rule, disable Threat Management, block a client, change a camera's recording mode. Before v0.9.0 the server trusted the LAN, which meant a single compromised IoT device on the same network had admin-equivalent access to the controller. v0.9.0 closes that gap. Access currently ships read-only, but the same bearer-token gate still applies to it.

## Generate a token

```bash
openssl rand -hex 32
```

Use one token per client (Claude Code, n8n, Home Assistant, etc.) so you can revoke one without rotating all.

## Configure the server

Set `MCP_UNIFI_AUTH_TOKENS` as a comma-separated list. Each entry is one of:

- a **bare token** (auto-assigned client_id `client-0`, `client-1`, ...) — **full access to every tool** (see the "Legacy token warning" below)
- a **`name:token` pair** for named clients (the name shows up in the audit log) — **full access to every tool** (also legacy)
- a **`name:token:module1|module2` triple** to scope a client to specific modules — pipe-separated because comma is the entry delimiter. Known modules are `network`, `protect`, `access`; `*` means all.

```env
MCP_UNIFI_AUTH_TOKENS=admin:7f3a...,n8n-flows:c812...:network|protect,camera-viewer:a4d9...:protect
MCP_UNIFI_AUTH_REQUIRED=true
```

In the example above, `admin` sees every tool, `n8n-flows` can only see Network and Protect, and `camera-viewer` only sees Protect. On `tools/list` a scoped client only sees the tools it's allowed to call; attempts to call a tool outside the scope return an auth error without leaking which other modules exist.

Note that **module scoping is not action scoping**: a client scoped to `network` can still call every Network tool, including destructive ones like `delete_vlan` or `create_port_forward`. If you need to publish an audit or observability workflow, pair the module scope with a client name that reflects the workflow (`n8n-flows`, `camera-viewer`), and only hand out tokens to processes that will actually restrict themselves to read tools. Per-tool RBAC is a v1.x decision.

On boot, the server logs the configured client_ids (never the tokens) and starts. Without tokens and with `MCP_UNIFI_AUTH_REQUIRED=true`, the server raises at startup with a clear error.

### Legacy token warning

Bare tokens and 2-part (`name:token`) entries stay valid for backward compatibility, but **treat them as full-access legacy tokens**. Every module is allowed, including destructive tools. When you're ready to tighten a deployment, migrate each token to the 3-part form and assign the narrowest module set that still lets the client do its job.

### Token format constraints

The parser splits each CSV entry on `:` up to two times, so **the token portion must not contain `:` or `|`**. The recommended `openssl rand -hex 32` produces hex-only output, which is safe. If you generate tokens with base64 or another scheme, verify no delimiter characters appear in the output before adding it to the env var. The server validates this at startup and refuses to boot on a token that would collide with the format.

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

## Enforcement surface

The bearer-token gate and per-client module scope apply to **every request that arrives over the Streamable HTTP transport** — that is the attacker-reachable surface. Concretely:

- `tools/list` responses are filtered per client_id.
- `tools/call` is rejected when the tool's module tag is outside the caller's allowed set.

Not covered by the transport-layer gate:

- **The `mcp-unifi-replay` CLI.** Replay builds a fresh, in-process FastMCP instance in the operator's shell and invokes tools programmatically. There is no HTTP request context, no bearer token, no client_id — it runs as the local operator. Treat replay the same as any other admin CLI: only run it on systems where you already trust the operator's shell access, and be aware that it can call tools regardless of any scope you set in `MCP_UNIFI_AUTH_TOKENS`.
- **Stdio transport.** Same reasoning: the parent process (Claude Desktop, `uvx`) owns the security boundary. Stdio ignores `MCP_UNIFI_AUTH_TOKENS` entirely.
- **Composite tools calling other Network tools.** As of writing, no tool body invokes another registered tool by name (composites go straight to the UniFi backend via `resolve_backend`). If a future tool adds an internal `tools/call` dispatch, the scope check would not fire on that inner call — write it to route through the backend layer instead.

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

- **Per-tool scopes**: scoping is per-module (`network` / `protect` / `access`), not per-tool. A client with `network` scope can call every Network tool, including destructive ones. Finer-grained per-tool scopes are a v1.x decision.
- **Token rotation API**: rotate by editing the env var and restarting. No live rotation endpoint.
- **OAuth flows**: out of scope. The static-token model fits homelab single-admin use; if you need OAuth, front mcp-unifi with an authenticating reverse proxy (Authelia, Caddy + auth_request, etc.) and keep `MCP_UNIFI_AUTH_REQUIRED=false`.
- **Rate limiting**: not implemented.
