# mcp-unifi: 6-Week Plan to v1.0

## Context

Pete owns `pete-builds/mcp-unifi` (v0.4.1, Python/FastMCP, 41 tools, 90% test coverage, dual transport, GHCR + uvx + official MCP Registry, Trivy-scanned, hardened). The technical foundation is strong. There are other UniFi MCP servers in the ecosystem with broader feature surface; the goal of v1.0 is not to out-feature them but to ship a coherent, well-documented option with a specific design point.

The win condition for v1.0 is **a single-image, opinionated, safety-first build with multi-site support, available where users actually look.** Quality + distribution + steady maintenance, not feature count.

**Scope decisions (Pete-approved, 2026-05-14):**
- **Keep the name `mcp-unifi`** — preserve v0.x equity, keyword SEO, existing MCP Registry entry. Differentiate on positioning, not naming.
- **Network + Protect modules** at v1.0. Skip Access/Drive (rare/niche; revisit post-v1.0 if requested).
- **Multi-site in v1.0** — the architectural commitment that's painful to retrofit. Single process, multiple named controllers via `MCP_UNIFI_CONTROLLERS_FILE` + a `controller` param on every tool.
- **Dry-run + audit log** on every destructive op — the safety differentiator.
- **No hosted demo, no Anthropic Connectors, no Discord, no separate domain** at v1.0. All are post-v1.0 options if traction warrants.
- **4 distributions** (Docker, .mcpb, uvx, Helm) + **4 catalog listings** (Smithery, Glama, mcp.so, PulseMCP).
- **6 weeks to v1.0** (~Jun 25, 2026).

**Intended outcome**: mcp-unifi 1.0 ships with safety-first defaults (dry-run + audit + rollback composites), multi-site support, Network + Protect coverage, available across the four distribution channels that actually matter, listed in every directory people browse.

---

## Critical Files to Modify or Create

### Existing repo
- `/Users/ps959/ai-cli-workspace/Mine/Self-Hosted/mcp-unifi/src/mcp_unifi/server.py` — split per-module dispatchers
- `src/mcp_unifi/clients/unifi.py` (316 LOC) — refactor into `clients/network.py`, add `clients/protect.py`
- `src/mcp_unifi/clients/stubs.py` (684 LOC) — add Protect stub state
- `src/mcp_unifi/config.py` — multi-controller schema (list of named sites)
- `Dockerfile`, `docker-compose.yml` — unchanged structurally; bump versions
- `.github/workflows/` — extend for cosign, SBOM, .mcpb build, Helm chart publish

### New scaffolding
- `manifest.json` + `.mcpb` build config (Desktop Extensions) — in repo
- `smithery.yaml` (Smithery deployment manifest) — in repo
- `charts/mcp-unifi/` (Helm chart) — in repo, published to GitHub Pages
- `docs/` — Astro Starlight docs site as a subpath/subdomain on existing infra (no separate domain)

### Reference patterns to reuse
- Composite-with-rollback pattern: `server.py:create_iot_network` and `provision_homelab_service` — extend the pattern to a Protect composite (camera setup with retention + motion zone)
- Stub mode pattern (`stubs.py` in-memory state machine) — replicate structure for Protect
- Pydantic-driven env config (`config.py`) — extend for multi-controller list with backward-compat
- Existing Trivy + GHCR workflow in `.github/workflows/` — extend with cosign keyless signing + Syft SBOM

---

## Phase 1 — Multi-Site Architecture + Audit + Dry-Run (Weeks 1–2)

**Goal**: Refactor for multi-site without breaking the existing 41 Network tools. Add the safety primitives (dry-run, audit) that become the v1.0 differentiator.

1. **Multi-site config**
   - `MCPUnifiConfig.controllers: list[ControllerConfig]` — each with `name`, `host`, `api_key`, `port`, `site`, `verify_ssl`
   - Backward-compat: existing single-controller env (`UNIFI_HOST`, `UNIFI_API_KEY`) auto-promoted to `controllers=[default]`
   - New: `MCP_UNIFI_CONTROLLERS_FILE` pointing to YAML for >1 controller
   - Tool signatures: every tool accepts optional `controller: str = "default"` parameter
2. **Module layout**
   - `src/mcp_unifi/modules/network/` (existing 41 tools, refactored into per-resource files)
   - `src/mcp_unifi/modules/protect/` (placeholder for Phase 3)
   - `src/mcp_unifi/dispatcher.py` — registers tools per module based on `MCP_UNIFI_MODULES_ENABLED` env (default: all)
3. **Dry-run wiring**
   - Every destructive tool (~20 of 41) accepts `dry_run: bool = False`
   - Returns predicted change set without applying
   - Stub mode honors dry-run too (consistent UX)
4. **Audit log**
   - `src/mcp_unifi/audit.py` — every tool call logged to JSONL: timestamp, controller, tool, args (with secrets scrubbed), result, success, latency
   - Configurable sink: file (default), stdout, syslog
   - Replay tool: `mcp-unifi-replay <audit.jsonl>` re-issues calls (useful for migrations and tests)
5. **Test refactor**
   - Move existing tests under `tests/network/`
   - Stub tests run multi-site (2 controllers) by default
   - Property-based tests for composite tools (Hypothesis) on rollback correctness

**Verification**: Existing 41 tools work unchanged in single-site mode. Multi-site test: spin two stub controllers, list devices on each, confirm isolation. Dry-run on `create_vlan` returns predicted change without writing. Audit log writes one line per call with secrets redacted.

---

## Phase 2 — Network Polish (Week 3)

**Goal**: Network module fully hardened with dry-run + audit + multi-site. Add the composite tools that justify "safer than raw API."

1. **Dry-run + audit support** to every destructive tool (carry-over from Phase 1 if not finished)
2. **New tools**
   - `audit_network_drift` — compare current state to a declared YAML spec, report diffs
   - `backup_config` / `restore_config` — controller-level snapshot and restore
3. **Composite tool review**: confirm `create_iot_network`, `provision_homelab_service`, `create_guest_network` all support `dry_run` and `controller` params with rollback-on-partial-failure
4. **Tool descriptions polish**: every tool's MCP description rewritten for LLM clarity (one-sentence purpose, bullet list of side effects, example args). This drives better LLM tool selection.

**Verification**: All ~25 destructive Network tools support dry-run. `audit_network_drift` against a stub spec returns expected diffs. Manual LLM test: ask Claude "create a guest VLAN with subnet 10.50.0.0/24" — single tool call, correct args, dry-run preview, then apply.

---

## Phase 3 — Protect Module (Week 4)

**Goal**: Ship UniFi Protect (NVR/cameras) coverage. Pete's homelab + most prosumer UniFi setups have Protect; this doubles the addressable use case.

1. **Protect client** (`src/mcp_unifi/clients/protect.py`)
   - UniFi Protect API: cookie-based auth, separate endpoint from Network API
   - HTTP client uses same httpx + retry pattern as Network client
2. **Protect tools** (~12 tools)
   - `list_cameras`, `get_camera`
   - `list_motion_events`, `list_smart_detections` (person/vehicle/animal)
   - `get_snapshot` (live frame), `download_clip` (event recording)
   - `list_recordings`, `set_camera_recording_mode`
   - `list_doorbell_events`, `unlock_doorbell` (if hardware supports)
   - Composite: `provision_camera` (recording schedule + retention policy + motion zone) with rollback
3. **Protect stub mode** (`src/mcp_unifi/clients/protect_stubs.py`)
   - 2 fake cameras (1 doorbell), fake motion events, fake snapshot bytes
   - Same audit + dry-run support as Network
4. **Tests**: full coverage parity with Network module (target: 90%+)

**Verification**: Stub Protect: list cameras, fetch fake snapshot, query motion events, run `provision_camera` then trigger failure mid-flow → rollback verified. Real Protect: validate against Pete's UCG-Fiber + Protect when hardware lands (tracked in `ucg-fiber-arrival.md`).

---

## Phase 4 — Distribution Builds (Week 5, first half)

**Goal**: Add the 3 new distribution channels. Docker and uvx already work.

1. **Desktop Extension (.mcpb)**
   - `manifest.json` per the [MCPB spec](https://github.com/anthropics/dxt)
   - GitHub Action that builds `mcp-unifi-{version}.mcpb` and attaches to releases
   - Bundles the Python runtime + dependencies (no separate install needed)
   - Configuration UI in Claude Desktop: stub mode toggle, controller list
2. **Helm chart** (`charts/mcp-unifi/`)
   - Deployment + Service + ConfigMap + optional Ingress
   - `values.yaml` covers: replicas, image tag, resources, controllers list (Secret-mounted), Prometheus scrape annotations
   - Liveness/readiness probes hit existing healthcheck
   - NetworkPolicy template (off by default, opt-in via values)
   - Published to `pete-builds.github.io/mcp-unifi-helm` via GitHub Pages action
3. **Smithery deployment**
   - `smithery.yaml` declares the Docker runtime + config schema
   - Connect repo to Smithery, enable auto-deploy on release
4. **Cosign-signed images + SBOM**
   - Keyless OIDC cosign signing in release workflow
   - Syft generates CycloneDX SBOM, attached to release
   - README documents `cosign verify` command
   - Skip SLSA L3 (theater for this audience)

**Verification**:
- `.mcpb`: download from a GitHub release, double-click on macOS → Claude Desktop installs it, tools appear, stub controller queryable
- Helm: `helm repo add mcp-unifi https://pete-builds.github.io/mcp-unifi-helm && helm install mcp-unifi mcp-unifi/mcp-unifi` on a kind cluster → pod healthy, tool call via port-forward succeeds
- Smithery: server appears on smithery.ai, install flow works
- `cosign verify ghcr.io/pete-builds/mcp-unifi:1.0.0 ...` → passes
- Syft SBOM downloadable from release page

---

## Phase 5 — Catalog Listings + Docs Site (Week 5, second half)

**Goal**: Ensure mcp-unifi appears wherever someone browses for an MCP server. Ship a real docs site without committing to a separate domain.

1. **Catalog submissions** (one-time, ~1 day total)
   - **Smithery**: already deployed in Phase 4; verify listing
   - **Glama**: submit via their GitHub auto-discovery + manual claim
   - **mcp.so**: submit via web form
   - **PulseMCP**: submit via curator form
   - **Awesome MCP lists**: PRs to `modelcontextprotocol/servers` README, `awesome-mcp-servers`, `mcpservers.org`
   - **MCP Registry (official)**: update existing entry with new version + module list
2. **Docs site** (Astro Starlight)
   - `pete-builds/mcp-unifi/docs/` — built and deployed via GitHub Action
   - Hosted at `mcp-unifi.brooksnewmedia.com` (subdomain on existing infra) or as `pete-builds.github.io/mcp-unifi`. Decide based on which is faster to wire.
   - Sections: Quickstart per channel (Docker, .mcpb, Helm, uvx), Tool Reference (auto-generated from FastMCP introspection where possible), Multi-Site Setup, Dry-Run + Audit, Security Model, Migration from v0.x, Changelog
   - Recipes: Claude Desktop, Claude Code, Cursor, Cline, Goose (one page each, copy-paste config + sample prompt)
3. **README overhaul**
   - Hero section: descriptive positioning (e.g. "Self-hosted UniFi MCP server. Multi-site, dry-run, audit log, Network + Protect.") — no comparative superlatives.
   - 4 install paths front and center (Docker, .mcpb one-click, Helm, uvx)
   - Badges: CI, coverage, MCP spec version, cosign-signed, OpenSSF Scorecard

**Verification**: Each catalog shows mcp-unifi v1.0. Docs site live, all 4 install paths verified on a clean machine. Cold-start test: a stranger lands on the docs site and gets a successful tool call within 5 minutes.

---

## Phase 6 — Launch (Week 6)

**Goal**: Ship v1.0.0 with a coordinated, low-key launch. No over-promising.

1. **Final QA pass**
   - End-to-end install test on each of the 4 channels (clean macOS, clean Ubuntu)
   - Conformance test against MCP spec (use `mcp-validate` if available, otherwise hand-check against the spec)
   - Performance benchmark: tool call latency p50/p95/p99 across both modules. Publish in docs.
   - Security audit pass (re-run Trivy + add Snyk free tier)
2. **One launch screencast** (3–5 min, on YouTube, embedded in README and docs)
   - "mcp-unifi 1.0: install in 60 seconds, multi-site demo, dry-run + audit safety"
3. **v1.0.0 release**
   - Git tag, release notes, attestations, .mcpb bundle, all 4 channels updated in lockstep via release workflow
4. **Coordinated launch posts**
   - Hacker News (Tuesday 9am ET): "Show HN: mcp-unifi 1.0 — safe, multi-site UniFi MCP server"
   - r/homelab + r/Ubiquiti + r/ClaudeAI threads (link to docs, not just GitHub)
   - Pete's Stack microblog post
   - Skip LinkedIn campaign and email outreach. Let it grow organically; revisit if traction is strong.
5. **GitHub Discussions enabled** (Q&A, Ideas, Show-and-Tell categories)
   - Skip Discord. GitHub Discussions handles 90% of community needs without the empty-room problem.
6. **mcp-unifi v0.x deprecation note**
   - Not a hard cutover (we kept the name). v0.4.x users upgrade naturally; the audit log + dry-run + multi-site are additive.
7. **Post-launch tracking** (private spreadsheet or simple dashboard)
   - GHCR pulls, .mcpb downloads, GitHub stars, catalog impressions, Discussions activity
   - Weekly review for first 4 weeks. Decide based on data whether to greenlight Access/Drive/Connectors/hosted-demo for v1.1.

**Verification**: v1.0.0 tag exists, all 4 distribution channels show v1.0.0, all 4 catalog listings show v1.0.0, docs site live, launch post on HN.

---

## Design choices (positioning language for README, blog posts, screencast)

1. **Safety primitives** — `dry_run=True` on every destructive op returns the predicted change set without writing. Composites capture pre-state and roll back applied steps on partial failure. Every tool call lands in a JSONL audit log with secrets scrubbed; `mcp-unifi-replay` replays a log against any controller.
2. **Single image, multi-controller** — one container runs Network and Protect together; one process manages multiple UniFi sites in parallel via `MCP_UNIFI_CONTROLLERS_FILE` and a `controller` parameter on every tool.
3. **Network + Protect scope** — Network on by default; Protect opt-in via `MCP_UNIFI_MODULES_ENABLED=network,protect`. Access and Drive are not in scope for v1.0.
4. **API-key-first auth** — local API key from Settings → Control Plane → Integrations. No username/password storage, no cloud account.
5. **Available everywhere** — Docker, .mcpb one-click, Helm, uvx. Listed on Smithery, Glama, mcp.so, PulseMCP, and the official MCP Registry.
6. **Supply-chain hardened** — cosign-signed images, CycloneDX SBOM per release, GitHub-attested build provenance, hash-locked Python deps, non-root read-only container, Trivy-scanned, 91%+ test coverage.

---

## Risk Mitigations

| Risk | Mitigation |
|---|---|
| Multi-site refactor regresses single-site users | Backward-compat env vars, comprehensive test matrix, beta channel for v1.0-rc.x. Document explicitly that single-site config still works. |
| Pete's UCG-Fiber hardware not arrived in time to validate Protect against real hardware | Stub mode validates the API surface; if real-hardware testing slips, ship v1.0 with "Protect: tested on stub, real-hardware confirmation in v1.0.1" note. Don't block launch. |
| .mcpb bundle build flakiness (newish tooling) | Budget 2 days slack in Phase 4. Fallback: ship v1.0 with .mcpb as "experimental" if needed. |
| Catalog submissions take longer than expected (manual review queues) | Submit at start of Phase 5, not end. Worst case: some catalogs catch up post-launch; not a launch blocker. |
| Launch falls flat (low HN traction, few stars) | Acceptable outcome. The product still exists, gets discovered through search and catalogs over time. The win is being maintained at month 12, not viral at week 1. |
| Scope creep mid-build (temptation to add Access or Connectors) | Park them in `ROADMAP.md` for v1.1. Decide based on real user requests after launch, not anticipation. |

---

## Verification — End-to-End Acceptance for v1.0

Run all of these on a clean machine before tagging v1.0.0:

1. `docker pull ghcr.io/pete-builds/mcp-unifi:1.0.0 && docker run --rm ghcr.io/pete-builds/mcp-unifi:1.0.0 --version` → prints `1.0.0`
2. `uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi --help` → shows tool catalog
3. Download `mcp-unifi-1.0.0.mcpb`, double-click on macOS → installs in Claude Desktop, tools appear
4. `helm repo add mcp-unifi https://pete-builds.github.io/mcp-unifi-helm && helm install mcp-unifi mcp-unifi/mcp-unifi` on kind → pod healthy
5. Smithery install flow works end-to-end
6. Multi-site test: configure 2 stub controllers, run `list_devices(controller="home")` and `list_devices(controller="office")` → isolated results
7. Dry-run test: `create_vlan(vlan_id=99, dry_run=True)` → returns predicted change without writing; `dry_run=False` → applies
8. Composite rollback test: `provision_homelab_service(...)` → trigger failure mid-flow → all changes rolled back, audit log shows the rollback
9. Audit replay: capture an audit log from #8, run `mcp-unifi-replay <log>` against a fresh stub → identical end state
10. `cosign verify ghcr.io/pete-builds/mcp-unifi:1.0.0 --certificate-identity-regexp '...' --certificate-oidc-issuer https://token.actions.githubusercontent.com` → ✓
11. SBOM downloads from release page, validates as CycloneDX
12. Docs site live; cold-start: stranger gets a successful tool call within 5 minutes
13. All 4 catalog listings show v1.0.0
14. Protect module: list cameras (stub), fetch snapshot (stub), provision_camera with rollback works

---

## Post-v1.0 Roadmap (decide based on actual demand, not pre-built)

- **v1.1**: Access module (doors, users, schedules) — if requested
- **v1.2**: Drive module — if requested
- **v1.3**: Anthropic Connectors / multi-tenant hosted — if Pete sees real interest in claude.ai hosted use
- **v1.4**: Hosted demo at a subdomain — if catalog conversion data suggests "try before install" matters
- **Future**: Discord, separate domain, AWS Marketplace, SLSA L3 — only if traction justifies the maintenance cost

---

## Memory Updates (after v1.0 ships)

- Update `ucg-fiber-arrival.md`: note v1.0 architecture (multi-site, modules), add Protect module config notes
- Add new memory: `mcp-unifi-v1.md` documenting the v1.0 architecture (multi-site, modules, audit, dry-run), distribution channels, release process
