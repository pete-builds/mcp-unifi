---
draft: false
title: Cline
description: Wire mcp-unifi into Cline (VS Code MCP client).
---

Cline reads MCP server config from the VS Code settings UI (Cline → MCP Servers) or directly from `cline_mcp_settings.json`.

## Streamable HTTP (Docker)

Start the container:

```bash
docker run -d --rm -p 3714:3714 -e STUB_MODE=true \
  --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
```

Add to `cline_mcp_settings.json`:

```json
{
  "mcpServers": {
    "unifi": {
      "transport": "streamable-http",
      "url": "http://localhost:3714/mcp",
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

For real mode against a gateway, run the container with `STUB_MODE=false`, `UNIFI_HOST`, and `UNIFI_API_KEY` — Cline's config doesn't change.

Reload the Cline panel after editing the file. The `unifi` server should appear under the MCP Servers list with a green dot.
