---
draft: false
title: Cursor
description: Wire mcp-unifi into Cursor's MCP config.
---

Cursor reads MCP server config from `.cursor/mcp.json` (project scope) or `~/.cursor/mcp.json` (user scope).

## Streamable HTTP (Docker)

Point Cursor at a running container:

```json
{
  "mcpServers": {
    "unifi": {
      "url": "http://localhost:3714/mcp"
    }
  }
}
```

Start the container in a separate terminal:

```bash
docker run -d --rm -p 3714:3714 -e STUB_MODE=true \
  --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
```

## Stdio (uvx)

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
        "UNIFI_API_KEY": "<your-local-api-key>"
      }
    }
  }
}
```

Restart Cursor after editing the config.
