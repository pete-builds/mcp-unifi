# mcp-unifi

<!-- mcp-name: io.github.pete-builds/unifi -->

**The safest UniFi MCP server. Multi-site, dry-run, audit log, Network + Protect.**

[![CI](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml/badge.svg)](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)](https://github.com/pete-builds/mcp-unifi)
[![cosign](https://img.shields.io/badge/cosign-signed-blue)](https://github.com/pete-builds/mcp-unifi/releases)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20Streamable%20HTTP-brightgreen.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An [MCP server](https://modelcontextprotocol.io/) for self-hosted UniFi gateway management. 46 Network tools (devices, VLANs, WLANs, firewall, switch ports, port forwards, observability, plus composites with rollback) and 12 Protect tools (cameras, motion events, smart detections, recording config). Every destructive tool accepts `dry_run=True` to preview without writing. Every call lands in a JSONL audit log. Every tool accepts a `controller` parameter so one server instance can manage multiple sites.

Speaks both **stdio** (Claude Desktop, `uvx`, `.dxt`) and **Streamable HTTP** (Docker, Helm). Talks to a UCG-Fiber, UDM Pro, or any UniFi OS gateway via the local API key. No Site Manager or cloud account required.

## Install

Four supported paths. Pick the one that matches how you run Claude.

### Docker

Long-running container, Streamable HTTP on port `3714`. Best for homelab and multi-client setups.

```bash
docker run --rm -p 3714:3714 -e STUB_MODE=true \
  ghcr.io/pete-builds/mcp-unifi:latest
```

### Claude Desktop (.dxt) — one-click

Download `mcp-unifi-<version>.dxt` from the [latest release](https://github.com/pete-builds/mcp-unifi/releases) and double-click. Configuration is through a built-in UI in Claude Desktop. The bundle ships the Python runtime; no separate install needed. Uses stdio transport.

### Helm

```bash
helm repo add mcp-unifi https://pete-builds.github.io/mcp-unifi/
helm install unifi mcp-unifi/mcp-unifi \
  --set unifi.host=192.168.1.1 \
  --set unifi.apiKey=<your-local-api-key>
```

### uvx / pipx

Quick one-off runs straight from the GitHub repo. Stdio transport.

```bash
uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

Pin a release with `@v0.5.0-rc.2` (or any tag) appended to the URL.

Full guides for each install path live in the [docs site](https://pete-builds.github.io/mcp-unifi/).

## What makes mcp-unifi different

- **Safe by default.** `dry_run=True` on every destructive op returns the predicted change set without writing. Composite tools (`create_iot_network`, `create_guest_network`, `provision_homelab_service`, `provision_camera`) roll back on partial failure. Every call lands in a JSONL audit log with secrets scrubbed. Other UniFi MCPs hand the LLM a raw firewall API.
- **Multi-site.** Manage home + office + parents' controllers from one MCP instance. Every tool accepts an optional `controller` parameter. Zero competing UniFi MCPs do this.
- **Network + Protect.** The two UniFi apps homelab actually uses, in one server. Network on by default; Protect opt-in via `MCP_UNIFI_MODULES_ENABLED=network,protect`.
- **Available everywhere.** Docker, .dxt one-click, Helm, uvx. Listed on Smithery and the official MCP Registry.

## Quick start

Fastest cold-start: Docker + Claude Code in stub mode, no hardware required.

1. Start the container:

   ```bash
   docker run -d --rm -p 3714:3714 -e STUB_MODE=true \
     --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
   ```

2. Register it with Claude Code:

   ```bash
   claude mcp add --transport http --scope user unifi http://localhost:3714/mcp
   ```

3. Verify the connection:

   ```bash
   claude mcp list
   ```

4. In a Claude Code session, ask: *"list my UniFi devices"*. You'll get two stubbed devices back.

5. When you're ready to point at a real gateway, drop stub mode:

   ```bash
   docker run -d --rm -p 3714:3714 \
     -e STUB_MODE=false \
     -e UNIFI_HOST=192.168.1.1 \
     -e UNIFI_API_KEY=<your-local-api-key> \
     --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
   ```

Generate the API key under **Settings → Control Plane → Integrations → Create API Key** on the gateway.

## Compared to alternatives

A factual comparison against the other actively-listed UniFi MCP servers. `?` means the project's README doesn't document the property.

| Project | Tools | Multi-site | dry-run | Audit log | Cosign-signed | Last commit |
|---|---|---|---|---|---|---|
| **mcp-unifi** | 46 Network + 12 Protect | ✓ | ✓ | ✓ | ✓ | Active |
| sirkirby/unifi-mcp | 166 | – | – | – | – | ? |
| claytono/go-unifi-mcp | 242 ops (Go) | – | – | – | – | ? |
| Other community UniFi MCPs | varies | – | – | – | – | mostly stale |

mcp-unifi trades raw tool count for safety primitives, multi-site, and supply-chain provenance. The premise: the LLM doesn't need 166 endpoints, it needs the 60 that cover the operations homelab actually does every week, with safe-by-default semantics on the destructive ones.

## Configuration

All config is read from environment variables (and `.env` when present). The five most common:

| Variable | Default | Notes |
|---|---|---|
| `STUB_MODE` | `true` | When `false`, real-mode controller config is required. |
| `UNIFI_HOST` | (empty) | Gateway IP or hostname. Required in real mode. |
| `UNIFI_API_KEY` | (empty) | Local API key. Required in real mode. |
| `MCP_UNIFI_MODULES_ENABLED` | `network` | Set to `network,protect` to enable Protect. |
| `MCP_UNIFI_CONTROLLERS_FILE` | (unset) | YAML file with named controllers for multi-site. |

Full env var reference and the multi-site YAML schema are in the [Configuration docs](https://pete-builds.github.io/mcp-unifi/reference/configuration/).

## Docs

- [Docs site](https://pete-builds.github.io/mcp-unifi/)
- [Network tool reference](https://pete-builds.github.io/mcp-unifi/reference/network/)
- [Protect tool reference](https://pete-builds.github.io/mcp-unifi/reference/protect/)
- [Multi-site setup](https://pete-builds.github.io/mcp-unifi/guides/multi-site/)
- [Dry-run and audit log](https://pete-builds.github.io/mcp-unifi/guides/dry-run-audit/)
- [Security model](https://pete-builds.github.io/mcp-unifi/guides/security/)
- [Migration from v0.x](https://pete-builds.github.io/mcp-unifi/guides/migration/)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE).
