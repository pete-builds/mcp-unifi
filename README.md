# mcp-unifi

<!-- mcp-name: io.github.pete-builds/unifi -->

**Safety-first MCP server for self-hosted UniFi. Dry-run previews, JSONL audit log, composite rollback. Network + Protect + Access.**

[![CI](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml/badge.svg)](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-91%25-brightgreen)](https://github.com/pete-builds/mcp-unifi)
[![cosign](https://img.shields.io/badge/cosign-signed-blue)](https://github.com/pete-builds/mcp-unifi/releases)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20Streamable%20HTTP-brightgreen.svg)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Install in Claude

Paste this into Claude Desktop's config file, put in your gateway's address and API key, then fully quit and reopen Claude Desktop. It runs the v0.28.0 release through `uvx` (install [uv](https://docs.astral.sh/uv/) first), reads your own network, and cannot change anything on it.

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

- **Where the file is.** macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`. Windows: `%APPDATA%\Claude\claude_desktop_config.json`. If the file already has an `mcpServers` block, add the `unifi` entry inside it.
- **Where the API key comes from.** On the gateway: **Settings → Control Plane → Integrations → Create API Key**. The config file is plain text on disk, so keep it as private as the key.
- **`STUB_MODE` is `false` on purpose.** The server's default is a simulator that answers with made-up devices. To try it with no gateway, set `STUB_MODE` to `true` and leave out the host and key. From 0.29.0, a gateway configured while stub mode is on gets a startup warning and a line on every answer saying the data is simulated; v0.28.0, which this config pins, says nothing.
- **`MCP_UNIFI_READONLY` is `true` on purpose.** Every tool that would change your network is hidden and refused. Remove that line when you want Claude to make changes; destructive tools still offer a `dry_run` preview.

The same thing for Claude Code:

```bash
claude mcp add --transport stdio --scope user unifi \
  --env MCP_TRANSPORT=stdio \
  --env STUB_MODE=false \
  --env MCP_UNIFI_READONLY=true \
  --env UNIFI_HOST=192.168.1.1 \
  --env UNIFI_API_KEY=<your-local-api-key> \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi@v0.28.0 mcp-unifi
```

**What has been tested where.** The `uvx` route: tested on macOS (Apple silicon) in stub mode. Windows: not tested yet. The one-click `.dxt` bundle on the releases page: built on Linux, and it fails at startup on macOS (and, for the same reason, cannot work on Windows). It is built for Linux x86_64 only, where Claude Desktop is in beta, and it has not been tried there. Details under [Install](#install).

## What it is

An [MCP server](https://modelcontextprotocol.io/) built around the assumption that LLM-driven infrastructure calls need guardrails. Every destructive tool accepts `dry_run=True` and returns the predicted change set without writing. Composite tools (`create_iot_network`, `create_guest_network`, `provision_homelab_service`, `provision_camera`) capture pre-state and roll back applied steps on partial failure. Every call — dry-run or real — lands in a JSONL audit log with secrets scrubbed; the included `mcp-unifi-replay` CLI can re-issue a log against a fresh controller.

Beyond the safety substrate: **Network** tools for devices, AP radio tuning, VLANs, WLANs, firewall, switch ports, port forwards, DHCP reservations, AP groups, observability, Threat Management / IDS-IPS, Honeypot, and Teleport VPN, plus opt-in **Protect** (cameras, motion events, smart detections, recording config) and **Access** (doors, credentials, visitors, badge events, hubs / readers). Every tool accepts a `controller` parameter so one server instance manages multiple UniFi sites. Speaks both **stdio** (Claude Desktop, `uvx`, `.dxt`) and **Streamable HTTP** (Docker, Helm). The full, always-current tool list is in the auto-generated [Tool Manifest](https://pete-builds.github.io/mcp-unifi/tools/). Works on any UniFi OS gateway running UniFi Network 9.x or newer (UDM, UDM Pro, UDM SE, UCG-Fiber, UCG-Ultra, UDR, UDW, UniFi OS Server), authenticated with a local API key from Settings → Control Plane → Integrations. Verified against a UCG-Fiber on UniFi OS 5.1.33 running UniFi Network 10.6.101 (2026-09-13). Firewall reads cover both the legacy rulesets (`list_firewall_rules`) and the Zone-Based Firewall (`list_firewall_policies`, `list_firewall_zones`), and `audit_open_ports` checks both, so a site that has migrated to zones is not reported as having no firewall. Legacy firewall writes (`create_firewall_rule` and friends) target `/rest/firewallrule`; zone policy writes (`create_firewall_policy`, `update_firewall_policy`, `delete_firewall_policy`) go through the official Integration API only, and the provisioning composites create a zone policy instead of a legacy rule on a zone-based site ([ADR 0009](https://github.com/pete-builds/mcp-unifi/blob/main/docs/decisions/0009-zone-policy-writes-use-the-integration-api-only.md)). Network and WLAN writes go through the official Integration API where the request maps onto it exactly, and fall back to the private API otherwise; `UNIFI_WRITE_API=private` keeps every write private ([ADR 0008](https://github.com/pete-builds/mcp-unifi/blob/main/docs/decisions/0008-network-and-wlan-writes-use-the-integration-api.md)). No Site Manager or cloud account required.

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

### Claude Desktop (.dxt bundle): built for Linux x86_64 only today

On macOS or Windows, use [Install in Claude](#install-in-claude) above instead. The `.dxt` bundle on the [releases page](https://github.com/pete-builds/mcp-unifi/releases) is built on a Linux x86_64 machine and carries compiled Python packages for that platform only. Started on macOS (Apple silicon, Python 3.13), the 0.28.0 bundle stops at its first import with `ImportError: cannot import name 'ArgsKwargs' from 'pydantic_core._pydantic_core'`. Windows has not been tried, but it needs Windows builds of the same packages, which the bundle does not contain. Claude Desktop for Linux exists as a beta (Ubuntu 22.04+ and Debian 12+, x86_64 and arm64, per [Anthropic's Linux page](https://code.claude.com/docs/en/desktop-linux)); this bundle only has x86_64 builds and has not been tried there. From 0.29.0 the bundle's manifest declares Linux as its only platform and Python 3.13 exactly. One bundle per platform is planned follow-up work.

Where it does apply: double-click the file and configure it in Claude Desktop's built-in form. The bundle includes the server and its Python dependencies but not a Python interpreter: its manifest launches `python`, which must be a Python 3.13 (the compiled packages are built for 3.13 exactly). Uses stdio transport.

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

Quick one-off runs straight from the GitHub repo. Stdio transport: the server's default transport is Streamable HTTP, so set `MCP_TRANSPORT=stdio`.

```bash
MCP_TRANSPORT=stdio uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

Pin a release by appending `@<tag>` to the URL, using a tag from the [releases page](https://github.com/pete-builds/mcp-unifi/releases). mcp-unifi is not published on PyPI, so install it from the git URL as shown.

Full guides for each install path live in the [docs site](https://pete-builds.github.io/mcp-unifi/).

## Design

- **Read-only mode.** `MCP_UNIFI_READONLY=true` makes the server structurally unable to change anything: mutating tools are hidden from `tools/list` *and* refused on `tools/call`, so naming a hidden tool gets a normal error envelope instead of a write. Classification is declared per tool at registration (`@audited("list_networks", mutates=False)`), never inferred from tool names — twelve mutating tools, `confirm_destructive_action` among them, carry no `create_`/`update_`/`delete_`/`set_` prefix. Registration fails if a tool has not declared a classification, so a new tool cannot default into being callable. Defense in depth on top of a read-only UniFi API key, not a replacement for it.
- **Safety primitives.** Every destructive tool accepts `dry_run=True` and returns the predicted change set without writing. Composite tools (`create_iot_network`, `create_guest_network`, `provision_homelab_service`, `provision_camera`) capture pre-state and roll back applied steps on partial failure. Every tool call lands in a JSONL audit log with secrets scrubbed; the included `mcp-unifi-replay` CLI can re-issue a log against a fresh controller.
- **Single image, multi-controller.** One container runs Network, Protect, and Access together. The same process manages multiple UniFi sites in parallel via the `controller` parameter and a YAML controllers file (`MCP_UNIFI_CONTROLLERS_FILE`). No need to run a separate process per controller.
- **API-key-first auth.** Uses the local API key from Settings → Control Plane → Integrations against the `/proxy/network/api` endpoint. No username/password storage, no cloud account, no Site Manager dependency.
- **Multi-channel distribution.** Docker, Helm chart, uvx, and a .dxt bundle for Claude Desktop (Linux x86_64 only today). Listed on the official MCP Registry. Container images are cosign-signed (keyless OIDC) with a CycloneDX SBOM attached to each release.
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

4. In a Claude Code session, ask: *"list my UniFi devices"*. You'll get three made-up devices back (a gateway, an access point and a switch).

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

All config is read from environment variables (and `.env` when present). The most common:

| Variable | Default | Notes |
|---|---|---|
| `STUB_MODE` | `true` | `true` answers from a simulator with made-up devices; set `false` to use your gateway, which then requires real-mode controller config. From 0.29.0, a gateway configured while this is `true` gets a startup warning and a notice on every tool result. |
| `UNIFI_HOST` | (empty) | Gateway IP or hostname. Required in real mode. |
| `UNIFI_API_KEY` | (empty) | Local API key. Required in real mode. |
| `MCP_UNIFI_READONLY` | `false` | When `true`, mutating tools are hidden and refused. See the [Security guide](https://pete-builds.github.io/mcp-unifi/guides/security/#read-only-mode). |
| `MCP_UNIFI_MODULES_ENABLED` | `network` | Set to `network,protect,access` to enable all three modules. |
| `MCP_UNIFI_CONTROLLERS_FILE` | (unset) | YAML file with named controllers for multi-site. |
| `MCP_UNIFI_OTEL_ENABLED` | `false` | Optional OpenTelemetry tracing, one span per tool call. Off by default and the SDK is not a dependency. See [Operations](docs/operations.md). |
| `UNIFI_API_KEY_FILE` | (unset) | Read the API key from a file (a Docker or Kubernetes secret mount) instead of `UNIFI_API_KEY`. Wins if both are set, and turns TLS verification on by default. |
| `UNIFI_ACCESS_API_KEY_FILE` | (unset) | File-backed form of `UNIFI_ACCESS_API_KEY`. |
| `UNIFI_OS_PASSWORD_FILE` | (unset) | File-backed form of `UNIFI_OS_PASSWORD`. |
| `MCP_UNIFI_AUTH_TOKEN_FILE` | (unset) | File holding one bearer token (or the full `MCP_UNIFI_AUTH_TOKENS` grammar). Adds to whatever `MCP_UNIFI_AUTH_TOKENS` defines. |
| `MCP_UNIFI_CLIENT_ID` | (unset) | Client name for the bare token in `MCP_UNIFI_AUTH_TOKEN_FILE`. |
| `UNIFI_PINNED_CERT` | (unset) | Path to the console's own certificate (PEM) from `mcp-unifi-pin-cert`. When set, that certificate is the only one the server will accept from this controller. See below. |

Full env var reference and the multi-site YAML schema are in the [Configuration docs](https://pete-builds.github.io/mcp-unifi/reference/configuration/).

### File-backed secrets

Every secret has a `_FILE` twin for Docker and Kubernetes secret mounts. The environment-variable form keeps working and is not deprecated by this release; the file form is opt-in and carries the hardened defaults inside it, so a controller configured by `api_key_file` verifies the gateway's TLS certificate unless you set `verify_ssl: false`. In a controllers YAML:

```yaml
- name: lan
  host: 192.168.1.1
  api_key: <inline key>            # verify_ssl stays false: self-signed console on a LAN
- name: datacenter
  host: unifi.example.com
  api_key_file: /run/secrets/unifi_api_key   # verify_ssl defaults to true here
```

A missing, empty or unreadable secret file fails startup with a message naming the controller and the field, never the contents. On every boot the server logs one line per controller still on the environment-variable shape or running with TLS verification off. That warning is the first step of a dated path (opt-in, then warn, then flip at a major release) recorded in [ADR 0007](docs/decisions/0007-hardening-is-opt-in-unless-the-hole-has-no-legitimate-configuration.md); nothing is refused. `docker-compose.yml` shows the secret mount.

### Certificate pinning

UniFi consoles present a self-signed certificate whose name list does not include the address you connect to, so ordinary TLS verification can never pass against one and `verify_ssl` defaults to off. Pinning closes that gap without a CA: record the console's certificate once, and from then on the server accepts that certificate and nothing else.

```bash
mcp-unifi-pin-cert 192.168.1.1 --out /etc/mcp-unifi/pins/home.pem
# prints the SHA-256 fingerprint; compare it against the console before trusting it
ssh root@192.168.1.1 'openssl x509 -in /data/unifi-core/config/unifi-core.crt -noout -fingerprint -sha256'
# the same fingerprint read on the console itself, over a channel the pin does not depend on
```

Then set `pinned_cert: /etc/mcp-unifi/pins/home.pem` on the controller in the YAML, or `UNIFI_PINNED_CERT` for the single-controller env form. A pinned controller verifies every connection against that certificate and fails closed if the console presents anything else; there is no fallback. If a firmware update regenerates the console certificate, requests fail with a message that names the re-pin command, and you re-run it with `--force` after checking the new fingerprint. The server never fetches and trusts a certificate on its own: the bootstrap is always this explicit command. Pass `--expect-fingerprint` to have it refuse a certificate that does not match what you read off the console. In the container, mount the pin read-only (the compose file shows where).

## How this is built

The engineering scaffolding around the tool surface (see the [Tool Manifest](https://pete-builds.github.io/mcp-unifi/tools/) for the current count), in case you want to know what's holding it up:

**Test discipline.** Unit, integration, and property-based (Hypothesis) tests; run `pytest --collect-only -q` for the current count. HTTP is mocked with respx so tests don't hit a real controller. Branch coverage is measured and CI fails below 80%.

**Code quality gates.** Ruff (pycodestyle, pyflakes, isort, flake8-bugbear, pyupgrade, simplify, flake8-bandit security ruleset, comprehensions) plus mypy strict (no implicit Any, unreachable code flagged, unused ignores flagged). Pre-commit hooks run lint, format, types, and regenerate the tool manifest with a drift check, so bad code never reaches CI.

**CI pipeline (5 jobs).** Every PR runs a lockfile-drift check, a version-surfaces check, lint + type check, and tests + coverage, independently of each other. A fifth job builds the Docker image (single-arch, not pushed) and runs the Trivy filesystem and image scans (HIGH/CRITICAL fails the build); it starts only after lint + type check and tests have passed. The multi-arch build happens in the release pipeline below.

**Release pipeline.** A `git tag vX.Y.Z` push triggers a multi-arch (linux/amd64 + linux/arm64) Docker build, cosign keyless signing via sigstore OIDC, SLSA build provenance attestation, CycloneDX SBOM via Syft attached to the GitHub release, a .dxt bundle for Claude Desktop (built on Linux, so Linux x86_64 only today), GHCR push with `vX.Y.Z` / `X.Y` / `latest` tags, and a check that the version in `docker-compose.yml`, the Helm chart, `manifest.json`, `server.json` and `pyproject.toml` already matches the tag. The release workflow does not bump any of them; it fails the release if one does not already match.

**Dependency hygiene.** Hash-pinned via `pip install --require-hashes`. A custom CI step verifies every pinned dep in `requirements.in` matches `requirements.lock` so no one can bump one without the other. Dependabot auto-merges safe patches. The base image is digest-pinned, not tag-pinned.

**Container hardening.** Runs as non-root UID 1000 with its login shell set to `nologin` and no home directory (the image still contains `/bin/sh`). The runtime protections come from the Compose file and the Helm chart, not from the image: read-only root filesystem, a 16MiB `/tmp` tmpfs, `no-new-privileges`, and, in the Helm chart, all Linux capabilities dropped (a plain `docker run` applies none of these; see [SECURITY.md](SECURITY.md)). Dedicated `/health` endpoint keeps the streamable-HTTP transport from logging 406 noise on every Docker healthcheck.

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
- [Authentication](https://pete-builds.github.io/mcp-unifi/guides/auth/)
- [Security model](https://pete-builds.github.io/mcp-unifi/guides/security/)
- [Migration from v0.x](https://pete-builds.github.io/mcp-unifi/guides/migration/)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)

## License

[MIT](LICENSE).
