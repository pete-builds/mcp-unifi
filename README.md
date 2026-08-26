# mcp-unifi

<!-- mcp-name: io.github.pete-builds/unifi -->

**Safety-first MCP server for self-hosted UniFi. Dry-run previews, JSONL audit log, composite rollback. Network + Protect + Access.**

[![CI](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml/badge.svg)](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)](https://github.com/pete-builds/mcp-unifi)
[![cosign](https://img.shields.io/badge/cosign-signed-blue)](https://github.com/pete-builds/mcp-unifi/releases)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20Streamable%20HTTP-brightgreen.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An [MCP server](https://modelcontextprotocol.io/) built around the assumption that LLM-driven infrastructure calls need guardrails. Every destructive tool accepts `dry_run=True` and returns the predicted change set without writing. Composite tools (`create_iot_network`, `create_guest_network`, `provision_homelab_service`, `provision_camera`) capture pre-state and roll back applied steps on partial failure. Every call — dry-run or real — lands in a JSONL audit log with secrets scrubbed; the included `mcp-unifi-replay` CLI can re-issue a log against a fresh controller.

Beyond the safety substrate: **Network** tools for devices, AP radio tuning, VLANs, WLANs, firewall, switch ports, port forwards, DHCP reservations, AP groups, observability, Threat Management / IDS-IPS, Honeypot, and Teleport VPN, plus opt-in **Protect** (cameras, motion events, smart detections, recording config) and **Access** (doors, credentials, visitors, badge events, hubs / readers). Every tool accepts a `controller` parameter so one server instance manages multiple UniFi sites. Speaks both **stdio** (Claude Desktop, `uvx`, `.dxt`) and **Streamable HTTP** (Docker, Helm). The full, always-current tool list is in the auto-generated [Tool Manifest](https://pete-builds.github.io/mcp-unifi/tools/). Works on any UniFi OS gateway running UniFi Network 9.x or newer (UDM, UDM Pro, UDM SE, UCG-Fiber, UCG-Ultra, UDR, UDW, UniFi OS Server), authenticated with a local API key from Settings → Control Plane → Integrations. Verified against UCG-Fiber fw 5.1.12.33296. No Site Manager or cloud account required.

## Install

Four supported paths. Pick the one that matches how you run Claude.

### Docker

Long-running container, Streamable HTTP on port `3714`. Best for homelab and multi-client setups.

HTTP transport refuses to start without a bearer token, so supply one:

```bash
export MCP_UNIFI_TOKEN=$(openssl rand -hex 32)
docker run --rm -p 3714:3714 \
  -e STUB_MODE=true \
  -e MCP_UNIFI_AUTH_TOKENS="$MCP_UNIFI_TOKEN" \
  ghcr.io/pete-builds/mcp-unifi:latest
```

Clients then send `Authorization: Bearer $MCP_UNIFI_TOKEN`. For throwaway local
testing on loopback only, `-e MCP_UNIFI_AUTH_REQUIRED=false` skips auth entirely;
never use it on an interface reachable by anything else, because every connected
client gets admin-equivalent access to the controller.

### Claude Desktop (.dxt) — one-click

Download `mcp-unifi-<version>.dxt` from the [latest release](https://github.com/pete-builds/mcp-unifi/releases) and double-click. Configuration is through a built-in UI in Claude Desktop. The bundle ships the Python runtime; no separate install needed. Uses stdio transport.

### Helm

```bash
helm repo add mcp-unifi https://pete-builds.github.io/mcp-unifi/
helm install unifi mcp-unifi/mcp-unifi \
  --set unifi.host=192.168.1.1 \
  --set unifi.apiKey=<your-local-api-key> \
  --set auth.tokens=$(openssl rand -hex 32)
```

The chart ships `auth.required: true` with `auth.tokens: ""`, so the pod will not
start until you set a token (or `--set auth.required=false`, which is only
appropriate for a trusted single-tenant cluster).

### uvx / pipx

Quick one-off runs straight from the GitHub repo. Stdio transport.

```bash
uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

Pin a release with `@v0.5.0-rc.2` (or any tag) appended to the URL.

Full guides for each install path live in the [docs site](https://pete-builds.github.io/mcp-unifi/).

## Design

- **Read-only mode.** `MCP_UNIFI_READONLY=true` makes the server structurally unable to change anything: mutating tools are hidden from `tools/list` *and* refused on `tools/call`, so naming a hidden tool gets a normal error envelope instead of a write. Classification is declared per tool at registration (`@audited("list_networks", mutates=False)`), never inferred from tool names — twelve mutating tools, `confirm_destructive_action` among them, carry no `create_`/`update_`/`delete_`/`set_` prefix. Registration fails if a tool has not declared a classification, so a new tool cannot default into being callable. Defense in depth on top of a read-only UniFi API key, not a replacement for it.
- **Safety primitives.** Every destructive tool accepts `dry_run=True` and returns the predicted change set without writing. Composite tools (`create_iot_network`, `create_guest_network`, `provision_homelab_service`, `provision_camera`) capture pre-state and roll back applied steps on partial failure. Every tool call lands in a JSONL audit log with secrets scrubbed; the included `mcp-unifi-replay` CLI can re-issue a log against a fresh controller.
- **Single image, multi-controller.** One container runs Network, Protect, and Access together. The same process manages multiple UniFi sites in parallel via the `controller` parameter and a YAML controllers file (`MCP_UNIFI_CONTROLLERS_FILE`). No need to run a separate process per controller.
- **API-key-first auth.** Uses the local API key from Settings → Control Plane → Integrations against the `/proxy/network/api` endpoint. No username/password storage, no cloud account, no Site Manager dependency.
- **Multi-channel distribution.** Docker, .dxt one-click for Claude Desktop, Helm chart, uvx. Listed on the official MCP Registry. Container images are cosign-signed (keyless OIDC) with a CycloneDX SBOM attached to each release.
- **Network + Protect + Access.** Network on by default; Protect and Access opt-in via `MCP_UNIFI_MODULES_ENABLED=network,protect,access`. Access ships read-only (door unlocks and credential issuance require session-token auth and are deferred). UniFi Drive is not in scope.

## Quick start

Fastest cold-start: Docker + Claude Code in stub mode, no hardware required.

1. Start the container. Auth is on by default, so mint a token first:

   ```bash
   export MCP_UNIFI_TOKEN=$(openssl rand -hex 32)
   docker run -d --rm -p 3714:3714 \
     -e STUB_MODE=true \
     -e MCP_UNIFI_AUTH_TOKENS="$MCP_UNIFI_TOKEN" \
     --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
   ```

2. Register it with Claude Code, passing the token:

   ```bash
   claude mcp add --transport http --scope user unifi http://localhost:3714/mcp \
     --header "Authorization: Bearer $MCP_UNIFI_TOKEN"
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
     -e MCP_UNIFI_AUTH_TOKENS="$MCP_UNIFI_TOKEN" \
     --name mcp-unifi ghcr.io/pete-builds/mcp-unifi:latest
   ```

Generate the API key under **Settings → Control Plane → Integrations → Create API Key** on the gateway.

## Configuration

All config is read from environment variables (and `.env` when present). The six most common:

| Variable | Default | Notes |
|---|---|---|
| `STUB_MODE` | `true` | When `false`, real-mode controller config is required. |
| `UNIFI_HOST` | (empty) | Gateway IP or hostname. Required in real mode. |
| `UNIFI_API_KEY` | (empty) | Local API key. Required in real mode. |
| `MCP_UNIFI_READONLY` | `false` | When `true`, mutating tools are hidden and refused. See the [Security guide](https://pete-builds.github.io/mcp-unifi/guides/security/#read-only-mode). |
| `MCP_UNIFI_MODULES_ENABLED` | `network` | Set to `network,protect,access` to enable all three modules. |
| `MCP_UNIFI_CONTROLLERS_FILE` | (unset) | YAML file with named controllers for multi-site. |
| `MCP_UNIFI_OTEL_ENABLED` | `false` | Optional OpenTelemetry tracing, one span per tool call. Off by default and the SDK is not a dependency. See [Operations](docs/operations.md). |

Full env var reference and the multi-site YAML schema are in the [Configuration docs](https://pete-builds.github.io/mcp-unifi/reference/configuration/).

## How this is built

The engineering scaffolding around the tool surface (see the [Tool Manifest](https://pete-builds.github.io/mcp-unifi/tools/) for the current count), in case you want to know what's holding it up:

**Test discipline.** ~880 tests across unit, integration, and property-based (Hypothesis) — see `pytest --collect-only` for the current count. HTTP is mocked with respx so tests don't hit a real controller. Coverage gated at 80% branch coverage in CI; current floor is 90%.

**Code quality gates.** Ruff (pycodestyle, pyflakes, isort, flake8-bugbear, pyupgrade, simplify, flake8-bandit security ruleset, comprehensions) plus mypy strict (no implicit Any, unreachable code flagged, unused ignores flagged). Pre-commit hooks run lint, format, types, and regenerate the tool manifest with a drift check, so bad code never reaches CI.

**CI pipeline (5 gated jobs).** Every PR runs lockfile-drift check → lint + type check → tests + coverage → multi-arch Docker build → Trivy filesystem and image scan (HIGH/CRITICAL fails the build). Each gates the next.

**Release pipeline.** A `git tag vX.Y.Z` push triggers a multi-arch (linux/amd64 + linux/arm64) Docker build, cosign keyless signing via sigstore OIDC, SLSA build provenance attestation, CycloneDX SBOM via Syft attached to the GitHub release, a .dxt bundle for Claude Desktop one-click install, GHCR push with `vX.Y.Z` / `X.Y` / `latest` tags, and an auto-bump of the example `docker-compose.yml` on main.

**Dependency hygiene.** Hash-pinned via `pip install --require-hashes`. A custom CI step verifies every pinned dep in `requirements.in` matches `requirements.lock` so no one can bump one without the other. Dependabot auto-merges safe patches. The base image is digest-pinned, not tag-pinned.

**Container hardening.** Runs as non-root UID 1000, no shell, no home directory. Read-only root filesystem enforced via Docker / Helm. `/tmp` is a 16MiB tmpfs. `no-new-privileges` set. All Linux capabilities dropped. Dedicated `/health` endpoint keeps the streamable-HTTP transport from logging 406 noise on every Docker healthcheck.

**Security posture.** Bearer-token authentication on the HTTP transport, secure by default (refuses to start without tokens). Audit log records each authenticated `client_id` per call with secret scrubbing on `api_key`, `passphrase`, `password`, `secret`, `token` substring matches. API keys wrapped in pydantic `SecretStr`. `SECURITY.md` with a private disclosure path.

**Distribution surface.** GHCR (signed multi-arch), Smithery (registered), MCP Registry (listed), Helm chart (Secret/Deployment/Service/Ingress/NetworkPolicy templates), .dxt bundle, uvx / pipx.

**Documentation discipline.** Astro Starlight site auto-deploys to GitHub Pages. The per-tool reference pages are generated from FastMCP introspection by `scripts/generate_tool_manifest.py`, and the pre-commit hook regenerates and drift-checks them so code and docs can't diverge. CHANGELOG follows Keep a Changelog format.

**Version discipline.** `pyproject.toml`, the git tag, the CHANGELOG entry, the Docker image tag, the docker-compose example, and the Helm chart `appVersion` all stay aligned because the release workflow enforces it. There is never a moment where the docs and the code disagree about what version this is.

## Development

Clone, install dev dependencies, and wire up the pre-commit hooks:

```bash
git clone https://github.com/pete-builds/mcp-unifi.git
cd mcp-unifi
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" pre-commit
pre-commit install
```

The pre-commit hooks run ruff (lint + format), mypy strict, and the tool
manifest generator. The manifest hook regenerates
`docs/site/src/content/docs/tools/` whenever any file under
`src/mcp_unifi/modules/` changes and fails the commit if the on-disk
manifest drifts from the registered tool surface. Run the tests with
`pytest`.

To regenerate the manifest manually:

```bash
python scripts/generate_tool_manifest.py        # write
python scripts/generate_tool_manifest.py --check  # CI-style drift check
```

## Docs

- [Docs site](https://pete-builds.github.io/mcp-unifi/)
- [Network tool reference](https://pete-builds.github.io/mcp-unifi/reference/network/)
- [Protect tool reference](https://pete-builds.github.io/mcp-unifi/reference/protect/)
- [Access tool reference](https://pete-builds.github.io/mcp-unifi/reference/access/)
- [Multi-site setup](https://pete-builds.github.io/mcp-unifi/guides/multi-site/)
- [Access setup](https://pete-builds.github.io/mcp-unifi/guides/access-setup/)
- [Dry-run and audit log](https://pete-builds.github.io/mcp-unifi/guides/dry-run-audit/)
- [Security model](https://pete-builds.github.io/mcp-unifi/guides/security/)
- [Migration from v0.x](https://pete-builds.github.io/mcp-unifi/guides/migration/)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE).
