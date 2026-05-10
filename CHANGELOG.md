# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.0] - 2026-05-10

### Added

- **stdio transport** alongside the existing Streamable HTTP transport.
  Selected via the new `MCP_TRANSPORT` env var (`stdio` |
  `streamable-http`, default `streamable-http` for back-compat with
  existing Docker deploys). Lets Claude Desktop / `uvx` users spawn the
  server per session without running a long-lived container.
- **PyPI package** entry in `server.json` so the MCP Registry advertises
  both the stdio (`uvx mcp-unifi`) and OCI (`ghcr.io/.../mcp-unifi`)
  install paths.
- Quick-start in the README leads with the stdio path for desktop
  users; Docker remains the recommendation for homelab / multi-client
  setups.
- Three config tests covering `MCP_TRANSPORT` (default, accepted
  values, invalid values), plus a `safe_repr` test for the new field.

### Changed

- Logging now writes to **stderr** instead of stdout. Required for
  stdio transport (stdout owns the JSON-RPC framing); harmless for
  the HTTP path. Docker and journald collect stderr by default.
- `docker-compose.yml` explicitly sets `MCP_TRANSPORT=streamable-http`
  so the compose path is independent of the package default.

### Notes for upgrading

- **Docker users**: no behavioral change. The image still binds to
  `:3714/mcp`. If you re-pull the `:latest` tag or pin to `0.4.0` and
  reuse your existing `.env`, everything continues to work.
- **PyPI / uvx users**: set `MCP_TRANSPORT=stdio` in your client's env
  block (see README). The package default is `streamable-http`, so
  forgetting the override would start an HTTP server you don't want.

## [0.3.0] - 2026-05-09

### Added — 26 new tools across four tiers

**Tier 1 — CRUD gap fills (4 tools):**

- `update_firewall_rule(rule_id, updates)`: patch fields on an existing rule.
- `create_port_profile`, `update_port_profile`, `delete_port_profile`:
  full CRUD over switch port profiles (PoE, native VLAN, tagged VLANs,
  forwarding mode).

**Tier 2 — high-frequency ops (12 tools):**

- `block_client(mac)`, `unblock_client(mac)`, `reconnect_client(mac)`:
  per-client commands via `/cmd/stamgr` (`block-sta`, `unblock-sta`,
  `kick-sta`).
- `set_port_state(device_mac, port_idx, enable?, poe_mode?, portconf_id?)`:
  PATCH a single switch port via the device's ``port_overrides`` array. Real
  mode reads the device first to preserve other port overrides.
- `restart_device(mac)`, `locate_device(mac, on?)`: device-level commands
  via `/cmd/devmgr` (restart, set-locate / unset-locate).
- `list_dhcp_leases`, `create_static_dhcp_lease`, `delete_static_dhcp_lease`:
  static DHCP reservations via the legacy `/rest/user` endpoint
  (`use_fixedip=true`).
- `list_port_forwards`, `create_port_forward`, `update_port_forward`,
  `delete_port_forward`: full CRUD over port-forward (DNAT) rules.

**Tier 3 — observability (7 tools):**

- `get_site_health`: per-subsystem status (wan, lan, wlan, www, vpn).
- `get_wan_status`: convenience wrapper that returns just the WAN record
  (link, ISP, public IP, throughput, latency).
- `list_events(limit?)`: recent controller events from `/stat/event`.
- `list_alarms(limit?, archived?)`: active or archived alarms from
  `/stat/alarm`.
- `trigger_speedtest`: kicks off a speed test via `/cmd/devmgr`.
- `get_speedtest_results(limit?)`: archived speed-test history.
- `list_top_talkers(limit?)`: DPI by-station report ranked by total bytes.

**Tier 4 — composites with rollback (4 tools):**

- `provision_homelab_service(name, mac, ip, network_id, ports?, wan_expose?)`:
  static lease + LAN_LOCAL accept rule + (optional) per-port forward rules
  in one call. Reverses every step on partial failure.
- `quarantine_client(mac, reason)`: block client + structured warning log
  carrying the reason for later forensics.
- `create_guest_network(name, ssid, passphrase, vlan_id, schedule?, ...)`:
  guest-purpose VLAN + guest SSID (client isolation) + LAN_IN drop rule,
  with rollback on partial failure (matches `create_iot_network` pattern).
- `audit_open_ports`: read-only review that lists active port forwards and
  WAN-facing ``accept`` rules (with the boilerplate established/related
  rule filtered out). No writes.

### Changed

- Stub seed grew a third device (a `USW24PoE` switch with a 24-port table)
  so port-state tools have a realistic target. `_seed_clients` now also
  carries ``tx_bytes``/``rx_bytes`` so `list_top_talkers` ranks
  meaningfully in stub mode.
- `StubState` gained an `audit_log` list capturing every block / unblock /
  reconnect / restart / locate / set_port_state action with timestamps.

### Tests

- Tool count: 15 → 41. Test count: 126 → 224. Coverage: 90% (well above
  the 80% gate).
- Tier 4 composites have full rollback coverage in stub mode (every
  failing step + the rollback-delete-failure path), plus real-mode HTTP
  rollback for `provision_homelab_service`.

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

[0.4.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.4.0
[0.3.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.3.0
[0.2.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.2.0
[0.1.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.1.0
