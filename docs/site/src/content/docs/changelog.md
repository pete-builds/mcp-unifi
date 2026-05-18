---
draft: false
title: Changelog
description: Notable changes across mcp-unifi releases.
---

The full, authoritative changelog lives in [`CHANGELOG.md`](https://github.com/pete-builds/mcp-unifi/blob/main/CHANGELOG.md) in the repo. This page mirrors the high points so you can scan recent releases without leaving the docs.

The project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) and the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

## [0.5.0-rc.2] — 2026-05-14

Phase 2 polish on top of rc.1: drift audit, backup/restore, and LLM-readable tool descriptions across all 46 tools. Existing tool behavior unchanged; signatures unchanged.

**Added**

- `audit_network_drift`: compare current controller state to a YAML spec, return a structured diff (missing / extra / drift). Matches resources by name (case-insensitive).
- `backup_config`: snapshot controller state into a versioned JSON envelope (`schema=1`). WLAN passphrases stripped to a sentinel; envelope flagged `secrets_stripped: true`.
- `restore_config`: compute an action plan from a backup envelope and apply it with rollback on partial failure. Restored WLANs from a secrets-stripped envelope are recreated with `enabled=False`.
- **Tool description rewrites** across all 46 tools: verb-first one-line purpose, `Side effects:` bullets, `dry_run` hint on destructive tools, `Rollback:` contract on composites, an `Example:` line with realistic args, and per-parameter docstrings on `controller` and `dry_run`.

**Tests**

- 383 tests passing (+37 from rc.1). 90% coverage maintained.
- New: `tests/network/test_drift.py`, `tests/network/test_backup_restore.py` (includes a Hypothesis property test for backup-mutate-restore convergence), `tests/test_tool_descriptions.py`.

## [0.5.0-rc.1] — 2026-05-14

Phase 1: multi-site, dry-run, and audit log. Single-controller users running v0.4.x see no behavioral change in real mode; legacy `UNIFI_HOST` + `UNIFI_API_KEY` env vars still auto-promote to a one-controller config.

**Added**

- **Multi-site config**: `Settings.controllers: list[ControllerConfig]`. Every tool accepts an optional `controller: str = "default"` parameter that selects which controller the call routes to. Optional `MCP_UNIFI_CONTROLLERS_FILE` env var points at a YAML file for more than one controller.
- **Backward compat**: existing single-controller env vars auto-promote to `controllers=[ControllerConfig(name="default", ...)]`. No config change required for v0.4.x users.
- **`SecretStr` on `api_key`**: controller credentials are wrapped in Pydantic's `SecretStr`. `repr()` and structured logging never echo the raw key.
- **Module dispatcher**: `MCP_UNIFI_MODULES_ENABLED` env (default `"network"`) controls which modules register tools at startup.
- **Network module split**: the single 1000-line `server.py` was split into 10 files under `src/mcp_unifi/modules/network/`. No behavior change.
- **`Backend` protocol**: `StubBackend` and `RealBackend` share one async surface. Tools call `backend.X()` instead of branching on `settings.stub_mode`.
- **Dry-run on 27 destructive tools**: `dry_run: bool = False` returns the predicted change set without writing. Composite dry-runs return the full graph with placeholder IDs.
- **Audit log substrate**: `src/mcp_unifi/audit.py` writes one JSONL record per call. Configurable sink: file (default), stdout, syslog. Args containing `passphrase` / `api_key` / `password` / `secret` are scrubbed before emission.
- **`@audited` decorator**: wraps every tool registration so emit happens uniformly.
- **`mcp-unifi-replay` CLI**: re-issues calls from a JSONL audit log. Useful for migrations and reproducing test scenarios.
- **Hypothesis property tests**: rollback correctness on the four destructive composites. Hypothesis injects a failure at any sub-step and asserts post-failure stub state is byte-identical to the pre-call snapshot.
- **Multi-site test fixtures**: `two_controller_settings`, `two_controller_states`, `multi_site_server` in `tests/network/conftest.py`.

**Changed**

- Test layout: `tests/test_tools.py` (~3000 lines) split into `tests/network/` per source module. Test count: 224 → 346. Coverage: 91%.

## [0.4.1] — 2026-05-14

**Fixed**

- `create_port_forward` and `create_port_profile` no longer mask the underlying `UniFiError` with `"Attempt to overwrite 'name' in LogRecord"`. Renamed log `extra` keys to `forward_name` / `profile_name`.

## [0.4.0] — 2026-05-10

**Added**

- **stdio transport** alongside Streamable HTTP. Selected via the new `MCP_TRANSPORT` env var (default `streamable-http` for back-compat).
- stdio install path: `uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi`. Installs straight from the repo; pin a release with `@v0.4.0`.

**Changed**

- Logging now writes to **stderr** instead of stdout (required for stdio transport; stdout owns the JSON-RPC framing).

## [0.3.0] — 2026-05-09

**Added — 26 new tools across four tiers**

- **Tier 1 (CRUD gap fills)**: `update_firewall_rule`, `create_port_profile`, `update_port_profile`, `delete_port_profile`.
- **Tier 2 (high-frequency ops)**: `block_client`, `unblock_client`, `reconnect_client`, `set_port_state`, `restart_device`, `locate_device`, `list_dhcp_leases`, `create_static_dhcp_lease`, `delete_static_dhcp_lease`, `list_port_forwards`, `create_port_forward`, `update_port_forward`, `delete_port_forward`.
- **Tier 3 (observability)**: `get_site_health`, `get_wan_status`, `list_events`, `list_alarms`, `trigger_speedtest`, `get_speedtest_results`, `list_top_talkers`.
- **Tier 4 (composites with rollback)**: `provision_homelab_service`, `quarantine_client`, `create_guest_network`, `audit_open_ports`.

Tool count: 15 → 41. Test count: 126 → 224. Coverage: 90%.

## [0.2.0] — 2026-05-02

**Added**

- `delete_wlan`, `update_wlan`, `delete_firewall_rule`, `list_clients` MCP tools.

Tool count: 11 → 15. Test count: 101 → 126.

**Changed**

- Base image bumped to `python:3.14-slim` (digest-pinned).

## [0.1.0] — 2026-05-01

Initial public release. Eleven MCP tools, hardened Docker image (non-root, read-only fs, hash-pinned deps, Trivy-scanned), stub mode for hardware-free development, real mode for UCG-Fiber / UDM Pro / other UniFi OS gateways via the local API key.
