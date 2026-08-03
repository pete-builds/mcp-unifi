---
draft: false
title: Cursor
description: Wire mcp-unifi into Cursor's MCP config.
---

Cursor reads MCP server config from `.cursor/mcp.json` (project scope) or `~/.cursor/mcp.json` (user scope).

## Streamable HTTP (Docker)

Point Cursor at a running container. The HTTP transport is secure by default — every request needs an `Authorization: Bearer <token>` header:

```json
{
  "mcpServers": {
    "unifi": {
      "url": "http://localhost:3714/mcp",
      "headers": {
        "Authorization": "Bearer <paste-token-from-openssl-rand-hex-32>"
      }
    }
  }
}
```

Start the container in a separate terminal, passing the same token:

```bash
export MCP_UNIFI_TOKEN=$(openssl rand -hex 32)
docker run -d --rm -p 3714:3714 \
  -e STUB_MODE=true \
  -e MCP_UNIFI_AUTH_TOKENS="$MCP_UNIFI_TOKEN" \
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
