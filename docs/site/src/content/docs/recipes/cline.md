---
draft: false
title: Cline
description: Wire mcp-unifi into Cline (VS Code MCP client).
---

Cline reads MCP server config from the VS Code settings UI (Cline → MCP Servers) or directly from `cline_mcp_settings.json`.

## Streamable HTTP (Docker)

Start the container. The HTTP transport is secure by default and refuses to start without a bearer token, so mint one first:

```bash
export MCP_UNIFI_TOKEN=$(openssl rand -hex 32)
docker run -d --rm -p 3714:3714 \
  -e STUB_MODE=true \
  -e MCP_UNIFI_AUTH_TOKENS="$MCP_UNIFI_TOKEN" \
  --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
```

Add to `cline_mcp_settings.json`, passing the same token as an `Authorization` header:

```json
{
  "mcpServers": {
    "unifi": {
      "transport": "streamable-http",
      "url": "http://localhost:3714/mcp",
      "headers": {
        "Authorization": "Bearer <paste-token-from-openssl-rand-hex-32>"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

For real mode against a gateway, run the container with `STUB_MODE=false`, `UNIFI_HOST`, and `UNIFI_API_KEY` — Cline's config doesn't change beyond the token header.

Reload the Cline panel after editing the file. The `unifi` server should appear under the MCP Servers list with a green dot.
