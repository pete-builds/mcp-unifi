---
draft: false
title: Claude Code
description: Register mcp-unifi with Claude Code over Streamable HTTP or stdio.
---

Claude Code is the fastest path to a working tool call. It supports both **Streamable HTTP** (point it at a running Docker container) and **stdio** (spawn `uvx mcp-unifi` per session).

## Streamable HTTP (Docker)

Start the container if you haven't already. The HTTP transport is secure by default and refuses to start without a bearer token, so mint one first:

```bash
export MCP_UNIFI_TOKEN=$(openssl rand -hex 32)
docker run -d --rm -p 3714:3714 \
  -e STUB_MODE=true \
  -e MCP_UNIFI_AUTH_TOKENS="$MCP_UNIFI_TOKEN" \
  --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
```

Register it with Claude Code at user scope, passing the token as an `Authorization` header:

```bash
claude mcp add --transport http --scope user unifi http://localhost:3714/mcp \
  --header "Authorization: Bearer $MCP_UNIFI_TOKEN"
```

Verify:

```bash
claude mcp list
```

Expected output:

```text
unifi: http://localhost:3714/mcp (http) - Connected
```

## Stdio (uvx)

For when you'd rather not run a container. Claude Code spawns the server as a subprocess for each session:

```bash
claude mcp add --transport stdio --scope user unifi \
  --env STUB_MODE=true \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

For real mode, pass gateway env vars instead:

```bash
claude mcp add --transport stdio --scope user unifi \
  --env STUB_MODE=false \
  --env UNIFI_HOST=192.168.1.1 \
  --env UNIFI_API_KEY=<your-local-api-key> \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

## Sample prompts

Once registered, these prompts hit the right tools:

- **"list my UniFi devices"** → `list_devices`
- **"create a guest VLAN on 10.50.0.0/24 with SSID 'guests' and passphrase 'hunter2hunter2'"** → `create_guest_network` (often with `dry_run=True` first if Claude has been told to be cautious)
- **"show me motion events from the front camera in the last hour"** → `list_motion_events` (requires Protect enabled)
- **"what ports do I have forwarded to the outside?"** → `list_port_forwards` or `audit_open_ports`
- **"is my controller's config drifted from the YAML spec at infra/unifi.yaml?"** → `audit_network_drift`
- **"snapshot my UniFi config to backup.json"** → `backup_config` (and pipe the response to a file from your shell)

## Multi-site

If you have more than one controller, register the server with `MCP_UNIFI_CONTROLLERS_FILE` configured (see [Multi-Site Setup](/mcp-unifi/guides/multi-site/)). Then in Claude Code:

- **"list devices on the office controller"** → `list_devices(controller="office")`
- **"create a guest VLAN on the home controller, dry-run first"** → `create_guest_network(..., controller="home", dry_run=True)`

## Tool descriptions for LLM clarity

Every tool's MCP description follows a consistent pattern: a verb-first one-line purpose, a `Side effects:` block, a `dry_run` hint on destructive tools, and an `Example:` line with realistic args. This is what drives reliable tool selection — Claude Code rarely needs to ask which tool to use, even on first-touch setups.
