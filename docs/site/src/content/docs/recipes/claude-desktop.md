---
draft: false
title: Claude Desktop
description: Configure Claude Desktop to use mcp-unifi over stdio or Streamable HTTP.
---

Claude Desktop supports MCP servers over both **stdio** (the server is a subprocess Claude Desktop spawns per session) and **Streamable HTTP** (the server is a long-running container that Claude Desktop dials). On macOS and Windows, the `uvx` config below is the way in today: the [.dxt bundle](/mcp-unifi/install/dxt/) is built for Linux x86_64 only and fails at startup on macOS.

`claude_desktop_config.json` lives at:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

After editing, **fully quit and relaunch Claude Desktop** for the change to take effect. The `uvx` command comes from [uv](https://docs.astral.sh/uv/); install it first.

**Tested where:** the `uvx` configs on this page were tested on macOS (Apple silicon) in stub mode. Not yet tested on Windows.

## Stdio (uvx): your network, read-only

The recommended first config. It reads your own gateway and cannot change anything on it, and it is pinned to a release:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/pete-builds/mcp-unifi@v0.28.0",
        "mcp-unifi"
      ],
      "env": {
        "MCP_TRANSPORT": "stdio",
        "STUB_MODE": "false",
        "MCP_UNIFI_READONLY": "true",
        "UNIFI_HOST": "192.168.1.1",
        "UNIFI_API_KEY": "<your-local-api-key>"
      }
    }
  }
}
```

`STUB_MODE` must be `false`: its default is `true`, which answers from a simulator with made-up devices even when a host and key are set. (When that happens the server logs a warning and every answer says the data is simulated.) `MCP_UNIFI_READONLY=true` hides and refuses every tool that would change your network; remove it when you want Claude to make changes.

## Stdio (uvx): stub mode

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

Start a new conversation and ask "list my UniFi devices". You'll get three made-up devices back (a gateway, an access point and a switch).

## Stdio (uvx): real mode with writes

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

Note that `claude_desktop_config.json` is **plaintext on disk**. If the API key matters, prefer the Docker / HTTP path below. (The [.dxt install](/mcp-unifi/install/dxt/) marks the key field sensitive, but it is built for Linux x86_64 only today.)

## Streamable HTTP (remote container)

Point Claude Desktop at a running Docker container (on this machine or another host on your network). The HTTP transport is secure by default, so every request needs an `Authorization: Bearer <token>` header, and the container must have been started with the same token (see the [Docker install guide](/mcp-unifi/install/docker/)):

```json
{
  "mcpServers": {
    "unifi": {
      "transport": "streamable-http",
      "url": "http://localhost:3714/mcp",
      "headers": {
        "Authorization": "Bearer <paste-token-from-openssl-rand-hex-32>"
      }
    }
  }
}
```

If the container is on another host, replace `localhost` with that host's name or IP. The container's transport must be `streamable-http` (the default for the published image). Without the `Authorization` header the server answers `401`.

## .dxt bundle (Linux x86_64 only today)

The `mcp-unifi-<version>.dxt` on the [releases page](https://github.com/pete-builds/mcp-unifi/releases) installs with a double-click and is configured through a form instead of JSON, but it is built on Linux and fails at startup on macOS. See the [.dxt install guide](/mcp-unifi/install/dxt/) for details.
