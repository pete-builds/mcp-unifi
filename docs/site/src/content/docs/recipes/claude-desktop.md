---
draft: false
title: Claude Desktop
description: Configure Claude Desktop to use mcp-unifi over stdio or Streamable HTTP.
---

Claude Desktop supports MCP servers over both **stdio** (the server is a subprocess Claude Desktop spawns per session) and **Streamable HTTP** (the server is a long-running container that Claude Desktop dials). The easiest path is the [.dxt one-click install](/mcp-unifi/install/dxt/); this page covers the manual `claude_desktop_config.json` approach for both transports.

`claude_desktop_config.json` lives at:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

After editing, **fully quit and relaunch Claude Desktop** for the change to take effect.

## Stdio (uvx) — stub mode

Try the tools with no UniFi hardware:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/pete-builds/mcp-unifi",
        "mcp-unifi"
      ],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "STUB_MODE": "true"
      }
    }
  }
}
```

Start a new conversation and ask "list my UniFi devices". You'll get two stubbed devices back.

## Stdio (uvx) — real mode

```json
{
  "mcpServers": {
    "unifi": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/pete-builds/mcp-unifi",
        "mcp-unifi"
      ],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "STUB_MODE": "false",
        "UNIFI_HOST": "192.168.1.1",
        "UNIFI_API_KEY": "<your-local-api-key>",
        "MCP_UNIFI_MODULES_ENABLED": "network,protect"
      }
    }
  }
}
```

Get the API key in the gateway UI under **Settings → Control Plane → Integrations → Create API Key**.

Note that `claude_desktop_config.json` is **plaintext on disk**. If the API key matters, prefer the [.dxt install](/mcp-unifi/install/dxt/) (encrypted storage) or the Docker / HTTP path below.

## Streamable HTTP (remote container)

Point Claude Desktop at a running Docker container (on this machine or another host on your network):

```json
{
  "mcpServers": {
    "unifi": {
      "transport": "streamable-http",
      "url": "http://localhost:3714/mcp"
    }
  }
}
```

If the container is on another host, replace `localhost` with that host's name or IP. The container's transport must be `streamable-http` (the default for the published image).

## .dxt one-click alternative

If hand-editing JSON is too much, download `mcp-unifi-<version>.dxt` from the [releases page](https://github.com/pete-builds/mcp-unifi/releases) and double-click. Configuration is through a built-in UI; no JSON to edit. See the [.dxt install guide](/mcp-unifi/install/dxt/) for details.
