# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-02

### Added

- `delete_wlan` MCP tool: removes a WiFi SSID by `_id`. Previously the
  underlying client method existed only to support `create_iot_network`'s
  rollback path.
- `update_wlan` MCP tool: patches an existing SSID. Accepts a partial dict
  of fields (name, hide_ssid, wpa_mode, x_passphrase, etc.); passphrases
  are redacted in the response.
- `delete_firewall_rule` MCP tool: removes a firewall rule by `_id`.
- `list_clients` MCP tool: returns connected wireless and wired clients
  with MAC, hostname, IP, signal/satisfaction (wireless), AP or switch
  port, and uptime/last_seen timestamps. Mirrors the controller's
  Insights → Clients view via the `/stat/sta` endpoint.
- Stub mode now seeds four realistic clients (two wireless with signal
  metrics, one wired NAS, one IoT device) so demos and tests have a
  meaningful surface to query.

Tool count goes from 11 to 15. Test suite grows from 101 to 126 tests at
unchanged 95% coverage.

### Changed

- Bumped runtime base image from `python:3.13-slim` to `python:3.14-slim`
  (digest-pinned). All dependencies provide Python 3.14 wheels.
- Bumped `uvicorn` 0.41.0 → 0.46.0 (websockets keepalive, contextvars
  isolation, `bytearray` body accumulation perf fixes).
- Bumped `python-dotenv` 1.1.0 → 1.2.2 (Python 3.14 support, symlink
  handling fixes; see breaking changes in their changelog if you call
  `set_key`/`unset_key` directly — this server does not).
- Bumped `docker/setup-qemu-action` 3 → 4 (Node 24 runtime).

### Security

- No CVEs fixed by this release; all dependency bumps are routine
  Dependabot updates with hash-pinned lockfile regeneration. Trivy fs and
  image scans remain at zero HIGH/CRITICAL findings.

## [0.1.0] - 2026-05-01

Initial public release.

### Added

- Eleven MCP tools for self-hosted UniFi gateway management:
  `list_devices`, `list_networks`, `create_vlan`, `update_vlan`, `delete_vlan`,
  `list_wlans`, `create_wlan`, `list_firewall_rules`, `create_firewall_rule`,
  `list_port_profiles`, and the composite `create_iot_network`.
- First-class **stub mode** with an in-memory state machine that mirrors a
  freshly-unboxed UCG-Fiber + U7 Pro deployment. Useful for development and
  for wiring up Claude Code flows before any hardware is on the network.
- **Real mode** that talks to a UCG-Fiber, UDM Pro, or other UniFi OS gateway
  via the local API key (`X-API-Key` header) over the legacy controller API
  at `/proxy/network/api/s/<site>/...`.
- **Rollback** for `create_iot_network`: if any step fails, all resources
  created earlier in the call are deleted (firewall rule → WLAN → VLAN). The
  response surfaces what was rolled back.
- **Hardened Docker image**:
  - Pinned base image by digest (`python:3.13-slim@sha256:...`)
  - Multi-stage build, slim runtime stage
  - Non-root user (UID 1000), no shell
  - Hash-locked Python deps installed with `--require-hashes`
  - `read_only` root filesystem in compose, `no-new-privileges`
  - Healthcheck via the `mcp_unifi.healthcheck` module
- **Structured JSON logging** with a defensive redactor that scrubs known
  sensitive keys (`api_key`, `passphrase`, etc.) from log records.
- **Pydantic Settings** for env-driven configuration with type/range
  validation at startup.
- **CI/CD**: GitHub Actions workflows for ruff lint, ruff format check, mypy
  strict, pytest with 80%+ coverage gate, Trivy fs and image scans, and a
  release workflow that publishes multi-arch (amd64/arm64) images to GHCR
  with SBOM, provenance, and a build attestation.
- **Dependabot** weekly updates for pip, Docker base image, and GitHub Actions.

### Acknowledgments

UniFi controller endpoint paths were cross-referenced against the
[`sirkirby/unifi-mcp`](https://github.com/sirkirby/unifi-mcp) project. No code
was copied; the implementation here is an independent FastMCP + httpx build.

[0.2.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.2.0
[0.1.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.1.0
