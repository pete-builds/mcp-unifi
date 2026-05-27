---
draft: false
title: Docker
description: Run mcp-unifi as a long-running container with Streamable HTTP transport.
---

The Docker image is the recommended install for homelab and multi-client setups. The server runs as a long-running process and answers MCP calls over Streamable HTTP on port `3714`. One container can serve Claude Desktop, Claude Code, Cursor, and Cline simultaneously.

## Quickstart (stub mode)

```bash
docker run --rm -p 3714:3714 -e STUB_MODE=true \
  ghcr.io/pete-builds/mcp-unifi:latest
```

That's the whole thing. The server boots into stub mode, returns realistic mock data, and needs no UniFi hardware. You can register it with any MCP client right now and start calling tools.

## docker-compose

A working compose file lives in the repo at `docker-compose.example.yml`:

```yaml
x-logging: &default-logging
  driver: json-file
  options:
    max-size: "10m"
    max-file: "3"

services:
  mcp-unifi:
    build: .
    image: mcp-unifi:dev
    container_name: mcp-unifi
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:size=16M
    ports:
      - "${MCP_PORT:-3714}:${MCP_PORT:-3714}"
    env_file:
      - .env
    environment:
      MCP_HOST: "0.0.0.0"
      MCP_PORT: "${MCP_PORT:-3714}"
      TZ: "${TZ:-UTC}"
      LOG_FORMAT: "text"
    logging: *default-logging
    healthcheck:
      test: ["CMD", "python", "-m", "mcp_unifi.healthcheck"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    security_opt:
      - no-new-privileges:true
```

The example builds from local source. For the published image, change `build: .` to `image: ghcr.io/pete-builds/mcp-unifi:latest` and drop the `build` key.

The container runs as **UID 1000**, no shell, with a **read-only root filesystem** (`/tmp` is `tmpfs`) and `no-new-privileges`.

## Verify

Send a `tools/list` request to confirm the server is alive and the right modules are loaded:

```bash
curl -sS -X POST http://localhost:3714/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

You should see 57 Network tools listed (or 68 if Protect is enabled).

## Switch to real mode

When you have a gateway and an API key, drop stub mode and add the gateway env vars:

```bash
docker run --rm -p 3714:3714 \
  -e STUB_MODE=false \
  -e UNIFI_HOST=192.168.1.1 \
  -e UNIFI_API_KEY=<your-local-api-key> \
  ghcr.io/pete-builds/mcp-unifi:latest
```

Get the API key from **Settings → Control Plane → Integrations → Create API Key** in the gateway UI.

For multi-site setups (more than one controller), use the `MCP_UNIFI_CONTROLLERS_FILE` env var instead. See the [Multi-Site Setup guide](/mcp-unifi/guides/multi-site/).

## Enable Protect

The Protect module is opt-in. Add `MCP_UNIFI_MODULES_ENABLED=network,protect`:

```bash
docker run --rm -p 3714:3714 \
  -e STUB_MODE=false \
  -e UNIFI_HOST=192.168.1.1 \
  -e UNIFI_API_KEY=<your-local-api-key> \
  -e MCP_UNIFI_MODULES_ENABLED=network,protect \
  ghcr.io/pete-builds/mcp-unifi:latest
```

See the [Protect Tools reference](/mcp-unifi/reference/protect/) for the full surface.

## Verify the image signature

Published images are signed with [cosign](https://docs.sigstore.dev/cosign/overview/) keyless OIDC. See the [Security Model guide](/mcp-unifi/guides/security/) for the verification command and SBOM download.
