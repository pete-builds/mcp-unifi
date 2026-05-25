# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-05-25

> **Bugfix release for UniFi Network 9.x (Zone-Based Firewall).** Two
> issues blocked Stage 6 of the home segmentation rollout against a real
> UCG-Fiber controller on 9.x: ``create_firewall_rule`` was using the
> pre-9.x rule_index band and was missing the network-conf type
> discriminator. Both are now fixed. No tool renames, no breaking
> signature changes.

### Fixed

- **``create_firewall_rule`` now works on UniFi Network 9.x.** Two
  controller-side validations were tripping the v0.6.0 tool:
  1. ``api.err.FirewallRuleIndexOutOfRange`` for any ``rule_index`` in
     the legacy 2000-3999 band. UniFi 9.x ZBF reserves the low bands for
     controller-managed rules; user rules must sit at ``20000`` and
     above. The tool's default is now ``rule_index=20000``.
  2. ``api.err.FirewallRuleNetworkConfTypeRequired`` whenever a rule
     references a network conf by ``_id``. The controller now requires a
     paired discriminator field. The tool emits
     ``src_networkconf_type`` / ``dst_networkconf_type`` (default
     ``"NETv4"``) alongside ``src_networkconf_id`` / ``dst_networkconf_id``.
     Address-only rules (CIDR via ``src_address`` / ``dst_address``) are
     unchanged: the discriminator is omitted when no ``_id`` is set.
- **Composite tools (``create_iot_network``, ``create_guest_network``,
  ``provision_homelab_service``) also bumped to the 9.x rule_index
  band** (``20000`` / ``20400`` baselines), since they hit the same
  ``OutOfRange`` failure when applied against a 9.x controller.

### Added

- **``src_networkconf_type`` and ``dst_networkconf_type`` parameters on
  ``create_firewall_rule``.** Both default to ``"NETv4"`` and are only
  emitted when the matching ``*_networkconf_id`` is set.

### Changed

- **Docstring on ``create_firewall_rule``** rewritten. Replaces the
  outdated "2000-3999 range, 2500 is a safe default" claim with the
  9.x ZBF reality (≥20000 for user-defined LAN_IN rules) and documents
  the new discriminator fields. Other agents (Apoc) read this docstring
  to learn the tool; accuracy matters here.

### Tests

- New: ``test_create_firewall_rule_default_rule_index_is_zbf_range``
  pins the default to the ≥20000 band.
- New: ``test_create_firewall_rule_omits_type_without_networkconf_id``
  pins the "no discriminator on address-only rules" contract.
- Updated: ``test_create_firewall_rule_with_networkconf_ids`` now
  asserts that both discriminators ride along with the network IDs.

### Background

The bugs surfaced during Apoc's Stage 6 rollout (matrix of 9 LAN_IN
rules across MGMT/TRUSTED/IoT/GUEST VLANs) against Pete's UCG-Fiber on
UniFi Network 9.x. Handoff brief lives in
``Mine/Self-Hosted/execution/.apoc-to-forge-handoff.md``.

## [0.6.0] - 2026-05-23

> **Network segmentation tool-surface release.** Fixes the
> ``api.err.ApGroupMissing`` failure on real-mode ``create_wlan`` against
> UCG-Fiber and fills three audit-driven gaps that surfaced while planning
> the network-segmentation rollout (VLAN per device tier + per-SSID firewall
> matrix). Behavior of every other tool is unchanged.

### Added

- **``list_ap_groups`` tool.** Read-only. Wraps the v2 controller endpoint
  ``/v2/api/site/<site>/apgroups`` and returns every AP group with ``_id``,
  ``name``, ``attr_hidden_id``, ``device_macs``, ``site_id``. Used by
  ``create_wlan`` to auto-resolve the controller's default AP group.
- **``update_static_dhcp_lease`` tool.** Convert or update an existing
  client to a fixed-IP reservation. Use this instead of
  ``create_static_dhcp_lease`` when the MAC already has a user record on
  the controller (any client that has ever connected). The controller
  rejects POST ``/rest/user`` for known MACs with ``api.err.MacUsed``;
  this tool resolves the existing ``_id`` via ``find_user_by_mac`` and
  PUTs the update to ``/rest/user/{_id}``.
- **``ap_group_ids`` and ``ap_group_mode`` parameters on ``create_wlan``.**
  When ``ap_group_ids`` is empty, the tool calls ``list_ap_groups`` and
  defaults to the group whose ``attr_hidden_id == "default"`` (falling back
  to the first group). ``ap_group_mode`` defaults to ``"all"`` so the new
  SSID broadcasts on every AP in the resolved group(s).
- **``src_port`` and ``dst_port`` parameters on ``create_firewall_rule``.**
  Enables port-scoped LAN_IN rules required by the segmentation matrix
  (e.g. IoT → MGMT:32400 for Chromecast → Plex). Single port, CSV
  (``"80,443"``), or range (``"3000-3100"``). Requires
  ``protocol="tcp"`` or ``protocol="udp"``.

### Fixed

- **``create_wlan`` no longer fails with ``api.err.ApGroupMissing``** on
  UniFi OS controllers. The controller rejected ``POST /rest/wlanconf``
  when the payload omitted ``ap_group_ids``; the tool now resolves and
  includes the default group automatically. Composites
  (``create_iot_network``, ``create_guest_network``) inherit the fix.
- **``create_vlan`` accepts both subnet forms.** UniFi stores
  ``ip_subnet`` as the gateway IP with mask (e.g. ``"10.0.50.1/24"``).
  Callers who pass the network form (``"10.0.50.0/24"``) get auto-promoted
  to gateway form before the POST, eliminating a class of silent failure.
  /24 only; other masks pass through unchanged.

### Tests

- New tests for ``list_ap_groups`` (stub + real + 500 path).
- New tests for ``create_wlan`` auto-resolving and honouring explicit
  ``ap_group_ids`` (real mode confirms the actual POST body carries
  ``ap_group_ids`` and ``ap_group_mode``).
- New tests for ``create_firewall_rule`` with ``dst_port`` set and unset
  (port fields omitted from the payload when empty).
- New tests for ``create_vlan`` subnet normalization (network form +
  gateway form both work).
- Existing composite real-mode tests updated to mock the apgroups endpoint
  alongside the legacy WLAN/network POSTs.

### Migration

No env var or transport changes. No breaking changes to existing tool
signatures; ``ap_group_ids`` and ``ap_group_mode`` on ``create_wlan`` and
``src_port`` / ``dst_port`` on ``create_firewall_rule`` are additive with
safe defaults. Existing callers continue to work; the ``api.err.ApGroupMissing``
failure on real-mode ``create_wlan`` is silently fixed on the first call.

---

## [0.5.1] - 2026-05-15

### Fixed

- **Dedicated `/health` endpoint.** Added a Starlette custom route at
  `/health` that returns 200 OK with body `"ok"`. The Docker healthcheck
  now hits this endpoint instead of `/mcp`, eliminating the `406 Not
  Acceptable` log line emitted on every healthcheck interval (every 30s)
  by the streamable-http MCP transport. Behavior of `/mcp` is unchanged.

---

## [0.5.0] - 2026-05-15

> **Stable release.** Promotes rc.1 + rc.2 to final, adds Phase 3 (UniFi
> Protect module), Phase 4 (distribution builds), and Phase 5 (docs site).
> Behavior of existing Network tools unchanged; all v0.4.x env vars still
> work. New capabilities are additive and opt-in.

### Added — Phase 3 (UniFi Protect Module)

- **12 Protect tools.** Read-only: `list_cameras`, `get_camera`,
  `list_motion_events`, `list_smart_detections`, `get_snapshot`,
  `get_event_thumbnail`, `list_recordings`, `list_doorbell_messages`.
  Destructive with `dry_run` support: `set_camera_recording_mode`,
  `set_camera_privacy_mode`, `set_motion_sensitivity`. Composite with
  rollback: `provision_camera` (recording mode + retention + sensitivity +
  privacy, rolls back applied steps on any failure).
- **`ProtectClient`.** Async httpx client for `/proxy/protect/api`, same
  `X-API-Key` auth as the Network client. Snapshot/thumbnail endpoints
  return raw bytes (base64-encoded in the tool response).
- **`ProtectStubState`.** In-memory state machine with 2 seed cameras (1
  G4 Doorbell, 1 G4 Pro), 5 motion events, 2 person smart-detections, tiny
  valid JPEGs for snapshots.
- **Opt-in.** Set `MCP_UNIFI_MODULES_ENABLED=network,protect` to enable.
  Default stays `network` only — no surface change for existing users.

### Added — Phase 4 (Distribution Builds)

- **`.dxt` Desktop Extension** for one-click install in Claude Desktop.
  `manifest.json` declares stdio transport and config UI for host, API key,
  stub mode, and modules. Built and attached to GitHub releases.
- **Helm chart** at `charts/mcp-unifi/`. Deployment + Service + Secret +
  Ingress (off) + NetworkPolicy (off). Published to GitHub Pages at
  `https://pete-builds.github.io/mcp-unifi/` via `chart-releaser-action`.
- **Smithery deployment manifest** (`smithery.yaml`). Docker runtime, config
  schema for host + API key + modules.
- **Cosign keyless signing** of container images via OIDC. Verify with
  `cosign verify ghcr.io/pete-builds/mcp-unifi:0.5.0
  --certificate-identity-regexp '...' --certificate-oidc-issuer
  https://token.actions.githubusercontent.com`.
- **Syft CycloneDX SBOM** attached to GitHub releases as a downloadable
  artifact (in addition to the OCI-attached SBOM from
  `docker/build-push-action`).

### Added — Phase 5 (Docs Site)

- **Astro Starlight docs site** at `docs/site/`, deployed to
  `https://pete-builds.github.io/mcp-unifi/` on push to main and on
  version tags. 21 pages: getting started, 4 install paths, 4 guides
  (multi-site, dry-run/audit, security, migration), 4 recipes (Claude
  Desktop, Claude Code, Cursor, Cline), 3 reference pages.
- **README overhaul.** Positioning, badges (CI, coverage, cosign, MIT),
  4 prominent install paths, factual comparison vs alternatives,
  quickstart, config table, links.

### Tests

- **461 tests passing** (was 383 at end of rc.2, +78 across Phase 3).
- **91% overall coverage.** `modules/protect/__init__.py`: 100%.
  `clients/protect.py`: 100%. `clients/protect_stubs.py`: 98%.

---

## [0.5.0-rc.2] - 2026-05-14

> **Release candidate.** Phase 2 polish on top of rc.1: drift audit,
> backup/restore, and LLM-readable tool descriptions across all 46 tools.
> Behavior of existing tools unchanged; signatures unchanged. Schema diff vs
> rc.1 is description-text only, plus 3 net-new tools.

### Added — Phase 2 (Network Polish)

- **`audit_network_drift`.** Read-only tool that compares current controller
  state to a YAML spec and returns a structured diff: missing resources, extra
  resources, and field-level drift across networks, WLANs, and firewall rules.
  Matches resources by `name` (case-insensitive). Useful for "is my controller
  in the state I declared?" workflows. Implemented in
  `src/mcp_unifi/modules/network/drift.py`.
- **`backup_config`.** Read-only snapshot of controller state into a versioned
  JSON envelope (`schema=1`): networks, WLANs, firewall rules, port profiles,
  static DHCP leases, port forwards. Skips transient data (clients, devices,
  observability). WLAN passphrases are stripped to a sentinel and the envelope
  is flagged `secrets_stripped: true` so restore can warn the operator.
- **`restore_config`.** Destructive tool (honors `dry_run`) that computes an
  ordered action plan to reach backup state from current state and applies it
  with rollback on partial failure. Cross-controller restore proceeds with a
  warning. Restored WLANs from a secrets-stripped envelope are recreated with
  `enabled=False` so the operator must reset passphrases before they go on the
  air. Implemented in `src/mcp_unifi/modules/network/backup.py`.
- **Tool description rewrites.** All 46 tools now follow a consistent pattern:
  verb-first one-line purpose, `Side effects:` bullets, `dry_run` hint on
  destructive tools, `Rollback:` contract on composites, an `Example:` line
  with realistic args, and per-parameter docstrings on `controller` and
  `dry_run`. Drives better LLM tool selection and is a real differentiator
  vs the 8 competing UniFi MCP servers.

### Changed

- **`scripts/compare_schemas.py`** gained a `--allow-description-changes` flag
  so Phase 2 description rewrites can be verified without flagging every tool
  as a regression. Param shapes (type, default, required) are still strictly
  enforced.
- **FastMCP description ordering** discovered: descriptions are truncated at
  the first Sphinx-style `Args:` block. All `Example:` lines moved to before
  `Args:` so they reach the LLM. Worth knowing for any future MCP server work.

### Tests

- 383 tests passing (was 346 at end of rc.1, +37 across Phase 2).
- 90% coverage maintained.
- New: `tests/network/test_drift.py` (15 tests),
  `tests/network/test_backup_restore.py` (17 tests, includes a Hypothesis
  property test for backup-mutate-restore convergence at 30 examples),
  `tests/test_tool_descriptions.py` (5 sanity tests).

### Backlog (not blocking)

- Composite `UnknownControllerError` propagation: `backup_config` and
  `restore_config` wrap unknown-controller errors in a clean envelope, but the
  4 Phase 1 composites + `audit_open_ports` let the error propagate as a raw
  exception. Both paths fail loudly so it's safe; the inconsistency is filed
  for v0.5.x cleanup.

---

## [0.5.0-rc.1] - 2026-05-14

> **Release candidate.** v0.5.0 stable awaits real-mode validation against
> Pete's UCG-Fiber. Single-controller users running v0.4.x see no behavioral
> change in real mode; legacy `UNIFI_HOST` + `UNIFI_API_KEY` env vars still
> auto-promote to a one-controller config. Multi-site, dry-run, and audit
> logging are additive.

### Added — Phase 1 (Multi-site, Dry-run, Audit)

- **Multi-site config.** `MCPUnifiConfig.controllers: list[ControllerConfig]`
  with `name`, `host`, `api_key`, `port`, `site`, `verify_ssl`. Optional
  `MCP_UNIFI_CONTROLLERS_FILE` env var points at a YAML file for >1
  controller. Every tool now accepts an optional `controller: str = "default"`
  parameter that selects which controller the call routes to.
- **Backward compat.** Existing single-controller env vars (`UNIFI_HOST`,
  `UNIFI_API_KEY`, `UNIFI_PORT`, `UNIFI_SITE`, `UNIFI_VERIFY_SSL`) auto-promote
  to `controllers=[ControllerConfig(name="default", ...)]`. No config change
  required for v0.4.x users.
- **`SecretStr` on `api_key`.** Controller credentials are now wrapped in
  Pydantic's `SecretStr`. Accessor `api_key.get_secret_value()` is required
  to read the cleartext; `repr()` and structured logging never echo the raw
  key. Existing logs already redacted the key; this hardens the in-memory
  representation too.
- **Module dispatcher.** `MCP_UNIFI_MODULES_ENABLED` env (default `"network"`)
  controls which modules register tools at startup. Currently only `network`
  ships; `protect` is reserved for Phase 3.
- **Network module split.** The single 1000-line `server.py` was split into
  10 files under `src/mcp_unifi/modules/network/` (vlans, wlans, firewall,
  port_profiles, clients, devices, dhcp, port_forwards, observability,
  composites). 43 tools, no behavior change, no schema change.
- **`Backend` protocol.** `StubBackend` (in-memory) and `RealBackend` (HTTP
  via `UniFiClient`) now share one async surface. Tools call `backend.X()`
  instead of branching on `settings.stub_mode`.
- **Dry-run on 27 destructive tools.** `dry_run: bool = False` parameter
  returns the predicted change set (payloads, predicted IDs, summary) without
  writing. Composite dry-runs return the full graph with placeholder IDs
  (`<dry-run-network-id>`, etc.) so callers can preview the shape end-to-end.
- **Audit log substrate.** `src/mcp_unifi/audit.py` writes one JSONL record
  per tool call: timestamp (UTC), controller, tool, scrubbed args, result
  shape, success flag, latency_ms. Configurable sink: file (default,
  `audit.jsonl`), stdout, or syslog. Args containing `passphrase`,
  `api_key`, `x_passphrase`, `password`, `secret` are scrubbed before
  emission.
- **`@audited` decorator.** Wraps every tool registration; emit happens
  uniformly so individual tool bodies stay clean.
- **`mcp-unifi-replay` CLI.** Re-issues calls from a JSONL audit log.
  Useful for migrations (export from controller A, replay against
  controller B) and reproducing test scenarios.
- **Hypothesis property tests.** Five property tests verify rollback
  correctness on the four destructive composites (`create_iot_network`,
  `create_guest_network`, `provision_homelab_service`, `quarantine_client`).
  For each, Hypothesis injects a failure at any of the composite's
  sub-steps and asserts that post-failure stub state is byte-identical to
  the pre-call snapshot. Deterministic CI profile pinned via
  `settings.register_profile("ci", deadline=None, derandomize=True)`.
- **`StubState.fail_next(method_name, exception)`.** Test helper that
  queues an exception to be raised on the next call to a named method.
  FIFO; multiple queued failures supported. Used by the property tests
  above. Purely additive — does not alter behavior outside of consuming
  a queued failure when one is present.
- **Multi-site test fixtures.** `two_controller_settings`,
  `two_controller_states`, `multi_site_server` in
  `tests/network/conftest.py`. Opt-in via explicit fixture request; per-
  resource tests still use single-controller defaults.

### Changed

- **Test layout.** `tests/test_tools.py` (~3000 lines) split into
  `tests/network/` per source module. Test count and assertions
  unchanged from v0.4.1; this is a pure reorganisation that mirrors the
  module split.
- Test count: 224 → 346 (added: dry-run, audit, replay-CLI, multi-site,
  property-rollback). Coverage: 91% (gate is 80%).

### Notes for upgrading

- **Single-controller users**: no action required. Set nothing new; the
  legacy env vars continue to work and auto-promote into the
  `controllers=[default]` shape internally.
- **Multi-controller users**: write a YAML file (one entry per
  controller) and point `MCP_UNIFI_CONTROLLERS_FILE` at it.
- **Audit log**: defaults to `audit.jsonl` in CWD. Set `MCP_UNIFI_AUDIT_SINK`
  to `stdout` or `syslog` to redirect, or `MCP_UNIFI_AUDIT_PATH` to choose
  a different file location.
- **Real-mode behavior unchanged** for single-controller users.

## [0.4.1] - 2026-05-14

### Fixed

- `create_port_forward` and `create_port_profile` no longer mask the
  underlying `UniFiError` with `"Attempt to overwrite 'name' in
  LogRecord"`. The exception handlers passed `extra={"name": name}` to
  `logger.exception`, colliding with Python logging's reserved
  `LogRecord.name` attribute. Renamed to `forward_name` /
  `profile_name`, matching the prefixed pattern already used by the
  VLAN, WLAN, and firewall-rule create paths.

## [0.4.0] - 2026-05-10

### Added

- **stdio transport** alongside the existing Streamable HTTP transport.
  Selected via the new `MCP_TRANSPORT` env var (`stdio` |
  `streamable-http`, default `streamable-http` for back-compat with
  existing Docker deploys). Lets Claude Desktop / `uvx` users spawn the
  server per session without running a long-lived container.
- stdio install path documented as `uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi`. Installs straight from the repo; pin a release with `@v0.4.0`. Skips PyPI entirely. (Original plan was a PyPI package; dropped to avoid the one-time PyPI account / publisher registration.)
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

[0.5.0-rc.1]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.5.0-rc.1
[0.4.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.4.0
[0.3.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.3.0
[0.2.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.2.0
[0.1.0]: https://github.com/pete-builds/mcp-unifi/releases/tag/v0.1.0
