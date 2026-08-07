# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.17.0] - 2026-08-06

Auth hardening + a new per-client tool-scoping feature. Security-relevant
changes to the token scope parser: three separate fail-closed fixes and one
durability fix to the audit log.

### Added

- **Per-client tool scoping by module.** Tokens can now carry an explicit
  module allow-list via the `client_id:token:module1|module2` scope form, so a
  caller can be given `network` without also receiving `protect` and `access`.
  When no scope is specified the token continues to inherit whatever the server
  has enabled, so existing tokens keep working.

### Security

- **Reject empty explicit scopes and fail closed on unresolved identity.**
  A token of the form `client_id:token:` (trailing colon, empty module list)
  is now rejected at parse time rather than being treated as "all modules".
  Callers whose identity cannot be resolved from the bearer token are denied
  instead of falling through to a default allow.
- **Fail closed on unknown module scopes and reserved delimiters.** Scope
  tokens containing modules the server does not know about, or tokens using
  reserved delimiters (`:` / `|`) inside the token secret itself, now fail
  the parse rather than being silently coerced.
- **Bumped `cryptography` 48.0.1 → 50.0.0** to clear GHSA-g6cj-pr64-35w5.
- **Audit log durability: `fsync` each JSONL line.** Previously the audit
  writer buffered lines and only flushed on close, so a crash between calls
  could lose the last few events. The server's "every tool call is recorded"
  claim is now true across an unclean shutdown.

### Changed

- Dependency bumps across the python-minor-patch group.
- `actions/checkout` bumped from 6 to 7 in CI.
- CI now runs `ruff format` and drops the gitignored `SESSION-RESUME.md`
  from the allowlist.
- Dockerfile comments corrected to describe the actual Python version and
  reproducibility framing.

### Fixed

- Release verify step (added in 0.16.1) now covers this release too — every
  version surface must match the tag before the build proceeds.

## [0.16.1] - 2026-08-03

Maintenance and dependency-security release. No tool behaviour changes: every
tool signature, envelope, and dry-run/confirm path is identical to 0.16.0.

### Security

- **Pinned `mcp==1.29.0` to clear three HIGH CVEs** (CVE-2026-52869,
  CVE-2026-52870, CVE-2026-59950). The transitive pin was reachable because
  `fastmcp==3.4.5` accepts `mcp<2.0,>=1.24.0` and the lockfile had resolved to an
  affected version. Pinned directly in `requirements.in` rather than waiting on a
  fastmcp release.
- Bumped `astro` to `^7.1.6` in `docs/site`, clearing 7 open Dependabot alerts,
  and bumped the docs `vite` transitive for CVE-2026-53571.

### Changed

- Dependency bumps across the python-minor-patch group and the `python` base
  image digest, via Dependabot.
- Regenerated `requirements.lock` and `requirements-dev.lock` to clear
  pre-existing pin drift (fastmcp, uvicorn, joserfc, python-multipart, ruff,
  mypy, hypothesis).

### Fixed

- **The documented Docker quick start could not start.** HTTP is the default
  transport and `auth_required` defaults to `True` with an empty `auth_tokens`,
  so `docker run -e STUB_MODE=true ghcr.io/pete-builds/mcp-unifi:latest` (the
  first command in the README, and the one on the docs homepage) raised
  `ValueError` and exited rather than serving. Broken since auth landed in
  0.9.0. Every install path in the README now mints and passes a bearer token,
  and shows the matching `--header "Authorization: Bearer ..."` for
  `claude mcp add`. The Helm example had the same defect, since the chart ships
  `auth.required: true` with `auth.tokens: ""`.
- **Release tags did not describe their own version.** The version files are
  bumped by `release.yml` *inside the runner* after checking out the pushed tag,
  and the bump is only committed to `main` after the build, so the tagged tree
  reported the previous version: `v0.16.0` contained
  `version = "0.15.4"` in `pyproject.toml`, `__init__.py`, and `manifest.json`.
  Installing from `@v0.16.0` therefore produced 0.15.4 metadata, and rebuilding
  the tag verbatim did not reproduce the released artifacts. Version files are
  now bumped in a commit *before* the tag is cut, so the tag names the exact
  source tree the artifacts were built from. The in-runner sed in `release.yml`
  is retained as a no-op safety net.
- **MCP Registry publishes landed one release behind**, the same root cause seen
  from the registry side. `publish-mcp.yml` takes its own checkout of the tag and
  read the stale `server.json`, so the registry sat on 0.15.4 while GHCR served
  0.16.0. It now derives the version from the tag name and waits for the image to
  land in GHCR first, so the `io.modelcontextprotocol.server.name` ownership
  label resolves instead of racing the build.
- **Audit replay silently lost the authenticated caller.** `AuditEvent.client_id`
  was written to the JSONL by `to_json`, but `parse_jsonl` never read it back, so
  every parsed or replayed event reported `client_id=None`. Logs predating the
  field still parse via the dataclass default, so the schema stays at `"1"`.
- Dropped an unused `# noqa: S310` in the healthcheck that `ruff 0.16.0` began
  flagging, unblocking CI on `main`.

## [0.16.0] - 2026-07-06

### Added

- **5xx retry with exponential backoff on idempotent reads.** The three service
  clients (`UniFiClient`, `ProtectClient`, `AccessClient`) now retry a `GET` that
  comes back `5xx` (e.g. the `503` a gateway returns under load or mid firmware
  upgrade) up to two extra times with exponential backoff (0.25s, 0.50s). The
  retry policy lives in one place (`mcp_unifi/clients/retry.py`) and is shared by
  every client HTTP helper. **Writes are never retried on a 5xx:** only `GET` is
  eligible, because the server drives changes through a dry-run/confirm/rollback
  model and a replayed `POST`/`PUT`/`DELETE` could double-apply. The existing
  single retry on a connection blip (`ConnectError`/`RemoteProtocolError`) is
  preserved unchanged.
- **`maxLength` bounds on free-text and secret tool parameters.** Reusable
  length-bounded `Annotated[str, Field(max_length=...)]` types
  (`mcp_unifi/modules/_params.py`) are applied to 30 free-text/secret params
  across the network tools (names 128, SSID 32, passphrases/passwords 128,
  hostnames/DNS 253, free text 256, YAML spec 200 000, backup JSON 5 000 000),
  publishing a `maxLength` constraint in each tool's input schema. This bounds
  what reaches the UniFi controller (an unbounded name would otherwise be
  forwarded verbatim). Identifier-style params (`*_id`, `mac`, `controller`) are
  intentionally left unbounded — they are structurally validated downstream.

## [0.15.4] - 2026-06-14

### Fixed

- **`set_lan_ipv6` `prefix_id` now actually carves a distinct /64 for a SECOND
  PD LAN.** v0.15.2 added an optional `prefix_id` (typed `str`) that wrote
  `ipv6_pd_prefixid` but ALSO flipped `ipv6_setting_preference` to `auto` on
  every PD enable. On UniFi Network 10.4.57 the controller's `auto` mode manages
  the sub-prefix carve itself and hands the primary slice (id 0) to ONE LAN (the
  Default/MGMT LAN), leaving a second auto PD LAN with an empty `ipv6_subnets` —
  so a pinned `prefix_id` was effectively ignored. Probed live 2026-06-14:
  Default = auto / id 0 -> `2606:380:2000:4ad::/64`; TRUSTED = auto / no id ->
  `ipv6_subnets=[]`.
- **The fix:** when `prefix_id` is supplied with `interface_type="pd"`, the tool
  now writes `ipv6_pd_prefixid=<id>` AND pins `ipv6_setting_preference="manual"`
  (it no longer flips to `auto` in this branch), because only manual mode honours
  an operator-pinned sub-prefix. Both keys are added to the patch, so the strict
  read-modify-write and the PD scaffold-fill preserve them. Verified live: TRUSTED
  (VLAN20) with `prefix_id=1` persisted both fields and carved its own distinct
  /64 from Empire's /56.

### Changed

- **`prefix_id` is now `int` (was `str`).** Default sentinel `-1` means "not
  supplied" (so `0`, a real distinct sub-prefix id, is preserved as a value).
  Omitting `prefix_id` keeps the legacy `auto` carve unchanged (back-compat for
  the primary MGMT/Default LAN). The tool manifest schema now exposes
  `prefix_id` as `type: integer`.

## [0.15.3] - 2026-06-14

### Fixed

- **`set_lan_ipv6` PD enable no longer 400s with `api.err.InvalidIpv6Addr` on a
  fresh LAN.** v0.15.2 fixed the WAN binding but only succeeded on the
  Default/MGMT LAN because that record already carried a leftover PD-window
  scaffold (`ipv6_pd_start=::2`, `ipv6_pd_stop=::7d1`) from a prior half-config,
  which the strict read-modify-write preserved. A genuinely fresh LAN (TRUSTED,
  IoT, GUEST — `ipv6_setting_preference=manual`, every `ipv6_*`/`dhcpdv6_*` key
  unset) has no such fields, so the merged record carried `ipv6_pd_start: null`
  and the controller rejected it (HTTP 400 `InvalidIpv6Addr`).
- **Comprehensive fix (full delta, not one field).** Computed live against the
  UCG-Fiber (UniFi Network 10.4.57) by diffing the WORKING Default LAN against a
  fresh blank LAN. When enabling `interface_type="pd"`, the tool now fills the
  COMPLETE PD scaffold a blank LAN lacks, copied verbatim from Default's working
  record:
  - `ipv6_pd_start` `::2`, `ipv6_pd_stop` `::7d1` (the PD window the controller
    demanded — the `null` culprit)
  - `dhcpdv6_start` `::2`, `dhcpdv6_stop` `::7d1`, `dhcpdv6_leasetime` `86400`
    (DHCPv6 lease window)
  - `ipv6_ra_priority` `high`, `ipv6_ra_preferred_lifetime` `14400` (RA lifetimes)
  - `ipv6_aliases` `[]`
  - `ipv6_setting_preference` flipped `manual` → `auto`: a manual LAN validates
    and persists but the controller will not auto-carve a sub-prefix for it, so
    it never gets a global /64. Default runs `auto`.
- **Scaffold is non-destructive.** Each default is applied ONLY when the live
  record lacks that key (absent/null) AND the caller did not set it explicitly,
  so an already-configured PD LAN (like Default) keeps its own window via strict
  read-modify-write. The WAN-binding auto-resolve, the optional `prefix_id`, and
  the `none`/`static` paths from v0.15.2/v0.15.1 are unchanged.
- **Live-verified on TRUSTED (VLAN20, the fresh-LAN proof):** the full
  fixed-code payload (`pd` + `wan` binding + complete scaffold +
  `ipv6_setting_preference=auto`) was applied to TRUSTED end-to-end; the
  controller returned HTTP 200 `rc:ok` and the networkconf now matches Default's
  working PD config exactly. TRUSTED IPv6 is left ENABLED. The gateway had not
  yet carved TRUSTED's runtime `/64` onto its VLAN20 interface at ship time; that
  carve requires a gateway provision cycle, which is out of scope for a
  TRUSTED-only IPv6 change (do not force-provision the shared gateway). Config is
  correct and accepted; runtime convergence is the gateway's to complete.
- New stub + real-mode regression tests assert a fresh LAN (no pre-existing
  ipv6 fields) emits a complete, non-null PD payload (`pd_start`/`stop`
  populated, `pd_interface=wan`, full lease/RA scaffold, `auto` preference), and
  that an already-configured PD LAN is not clobbered.

## [0.15.2] - 2026-06-14

### Fixed

- **`set_lan_ipv6` PD enable path no longer 400s with
  `api.err.PdRequiresAssignedDhcpv6Wan`.** Enabling prefix delegation on a LAN
  (`interface_type="pd"`) was rejected by the controller on every apply. Root
  cause, fixed and verified live against the UCG-Fiber (UniFi Network 10.4.57):
  - **Missing WAN-uplink binding.** A PD LAN networkconf must reference which
    DHCPv6 WAN's delegation it draws from via `ipv6_pd_interface` (the WAN's
    networkgroup, lowercased — `"wan"` on this gateway). The tool emitted only
    `ipv6_interface_type="pd"` and omitted the binding, so the controller
    rejected the merged record. Probed live: `ipv6_interface_type=pd` alone →
    HTTP 400 `PdRequiresAssignedDhcpv6Wan`; adding `ipv6_pd_interface="wan"` →
    HTTP 200 and the LAN receives a global /64.
  - The fix auto-resolves the binding from the WAN that actually has DHCPv6-PD
    enabled (`ipv6_wan_delegation_type=="pd"` + non-disabled `wan_type_v6`) and
    injects `ipv6_pd_interface` into the patch. When no WAN delegates a prefix,
    the tool returns a clear error pointing at `set_wan_ipv6` instead of letting
    the controller 400.
  - **New optional `prefix_id` param.** A hex sub-prefix id selecting which /64
    to carve from the delegated /56, sent as `ipv6_pd_prefixid` (only with
    `interface_type="pd"`). On UniFi Network 10.4.57 the controller auto-carves
    the sub-prefix and ignores this value; it is accepted for forward/
    cross-firmware compatibility.
  - Strict read-modify-write for all non-IPv6 keys and the `none`/`static`
    paths are unchanged. Added stub + real-mode regression tests pinning the
    WAN-binding payload, the `prefix_id` forwarding, and the no-delegation
    error.
  - **Live-verified:** the Default/MGMT LAN was enabled end-to-end through the
    fixed code path. The gateway carved `2606:380:2000:4ad::/64` from the
    delegated `2606:380:2000::/56` (gateway LAN address
    `2606:380:2000:4ad::1`) and a real client picked up the global address
    `2606:380:2000:4ad:a6bb:6dff:feac:287c`. Default IPv6 is left enabled.

## [0.15.1] - 2026-06-14

### Fixed

- **`set_wan_ipv6` enable path no longer 400s with `api.err.InvalidValue`.**
  Enabling DHCPv6-PD on the WAN (`connection_type="dhcpv6"` +
  `prefix_delegation="prefix-delegation"`) was rejected by the controller on
  every apply. Two root causes, both fixed and verified live against the
  UCG-Fiber (UniFi Network 10.4.57):
  - **Wrong delegation enum value.** The controller stores/accepts
    `ipv6_wan_delegation_type: "pd"`, not `"prefix-delegation"` (the literal
    `"prefix-delegation"` is rejected with `InvalidValue`). The tool now accepts
    the descriptive `"prefix-delegation"` alias (and the raw `"pd"`) and
    normalises it to the `"pd"` wire value before the PUT.
  - **Inconsistent PD-size pair.** The live WAN record carries
    `wan_dhcpv6_pd_size_auto: false` with no `wan_dhcpv6_pd_size` key. When
    enabling delegation the tool now always emits a self-consistent pair: an
    explicit `pd_size` pins `wan_dhcpv6_pd_size_auto=false` + that size;
    enabling delegation with no explicit size pins
    `wan_dhcpv6_pd_size_auto=true` so the controller auto-sizes.
  - The strict read-modify-write for all non-IPv6 keys, the disable path, and
    dual-WAN targeting are unchanged. Added stub + real-mode regression tests
    pinning the exact accepted payload.

## [0.15.0] - 2026-06-12

### Added

- **Network tool expansion: firewall groups, static routes, and v2 traffic
  policies (18 new Network tools).** All four endpoint families were verified
  live read-only against the UCG-Fiber (UniFi Network 10.4.57) before build;
  each returns an empty list on a fresh gateway. Reads return the records as-is;
  every mutating tool carries `dry_run=True`, and the deletes use the
  preview-then-confirm token flow (`confirm_destructive_action`). A new
  reusable client helper `_v2_request` wraps the `/proxy/network/v2/api/site/<site>/...`
  surface (bare-list responses, unlike the legacy `{meta, data}` envelope).
  - **Firewall groups** (`/rest/firewallgroup`, folded into the firewall
    module): `list_firewall_groups`, `get_firewall_group_details`,
    `create_firewall_group` (type one of `address-group` /
    `ipv6-address-group` / `port-group`), `update_firewall_group` (full-PUT
    read-modify-write; members replaced wholesale, `group_type` preserved),
    `delete_firewall_group` (preview-token).
  - **Static routes** (`/rest/routing`, new `routing` module):
    `list_routes`, `get_route_details`, `create_route` (CIDR destination +
    next-hop + administrative distance), `update_route`, `delete_route`
    (preview-token).
  - **Traffic rules** (v2 `/trafficrules`, new `traffic` module):
    `list_traffic_rules`, `get_traffic_rule_details`, `create_traffic_rule`,
    `update_traffic_rule` (read-modify-write), `toggle_traffic_rule`
    (enable/disable).
  - **Traffic routes** (v2 `/trafficroutes`, policy-based routing):
    `list_traffic_routes`, `get_traffic_route_details`, `update_traffic_route`
    (incl. `kill_switch_enabled`), `toggle_traffic_route`.
- Stub parity: seeded in-memory state for firewall groups, static routes,
  traffic rules, and traffic routes so the offline stub backend round-trips
  create/update/delete for each.
- **Network detail + DNS tools (10 new Network tools).** All endpoints were
  verified live read-only against the UCG-Fiber (UniFi Network 10.4.57) before
  build. Mutating tools carry `dry_run=True`; deletes use the
  preview-then-confirm token flow (`confirm_destructive_action`).
  - **Network detail** (`/rest/networkconf`, folded into the VLAN module):
    `get_network_details` — the deep, sectioned view that complements
    `list_networks`. Resolves a network by `network_id` or `name` and groups
    the record into `network` (identity), `dhcp` (all `dhcpd_*`/`dhcpdv6_*`),
    `ipv6` (LAN IPv6: `ipv6_interface_type`, `ipv6_ra_enabled`,
    `ipv6_client_address_assignment`, `ipv6_pd_start`/`ipv6_pd_stop`, RA
    tuning), `vpn`, and `raw` sections. (No `create_network`/`delete_network`
    added: `create_vlan`/`delete_vlan` already cover non-VLAN corporate LANs
    via the `purpose` parameter, so a generic pair would be redundant.)
  - **DNS content filtering** (v2 `/content-filtering`, new `content_filtering`
    module; the gateway's adblock/category-blocking profiles):
    `list_content_filters`, `get_content_filter_details`,
    `update_content_filter` (read-modify-write; list fields replaced
    wholesale), `delete_content_filter` (preview-token).
  - **Dynamic DNS** (`/rest/dynamicdns`, new `dynamic_dns` module):
    `list_dynamic_dns`, `get_dynamic_dns_details`, `create_dynamic_dns`
    (provider/host/login/password/interface; password redacted in previews and
    reads), `update_dynamic_dns`, `delete_dynamic_dns` (preview-token).
  - A static-DNS-records API (`/v2/.../dns-records`) returned 404 on this
    firmware, so no static-DNS-record tools were built (no live surface).
- Stub parity: seeded a sample content-filtering profile (so get/update/delete
  round-trip) and an empty Dynamic DNS collection (matching the live gateway;
  create/update/delete still round-trip).
- **Stats & insights read pack (6 new Network tools, all read-only).** Every
  endpoint was probed read-only against the live UCG-Fiber (UniFi Network
  10.4.57) before build; tools were shipped only where the firmware exposes a
  working surface. All six are in `READ_ONLY_TOOLS` (no `dry_run`). Backend
  shaping (`clients/stats_shape.py`) trims the noisy controller records to a
  compact, stable LLM-facing payload identical across the stub and real
  backends.
  - `get_system_info` (`/stat/sysinfo`) — controller version, build, hostname,
    uptime, device type, and update-availability flags.
  - `get_gateway_stats` (gateway `/stat/device` record) — CPU %, memory %,
    board/CPU/PMIC temperatures, throughput counters, client count, WAN IP.
  - `get_device_stats(mac)` (`/stat/device`) — per-device uptime, CPU/mem,
    satisfaction, client count, throughput, and (for APs) tx-retries/packets.
  - `get_client_stats(mac)` (`/stat/sta`) — per-client signal/RSSI/satisfaction,
    uptime, tx/rx bytes and rates, retries, anomalies; wired fields when wired.
  - `get_client_sessions(mac="", hours=24, limit=50)` (`POST /stat/session`) —
    recent connection sessions, newest first, with assoc time, duration,
    throughput, and roaming detail; optional per-client filter.
  - `get_anomalies` (`/stat/anomalies`) — client-impacting anomalies
    (e.g. `USER_HIGH_TCP_LATENCY`) with the affected MAC and occurrence times.
  - **Deferred (no live surface on this firmware, not shipped):** IPS/IDS
    threat events (`/stat/ips/event`, `/stat/ips/events`, `/rest/ips`,
    `/stat/threat` all 404/400) and the full DPI pack (`get_dpi_stats`,
    `get_site_dpi_traffic`, `list_dpi_applications`, `list_dpi_categories`) —
    DPI is unpopulated on this gateway and the app/category reference dicts
    (`/stat/dpiapp`, `/stat/dpigroup`) 404. **Skipped as duplicates:**
    `get_top_clients` (the existing `list_top_talkers` already wraps the DPI
    by-station view) and `get_network_health` (the existing `get_site_health`
    already passes the full `/stat/health` per-subsystem record through).
- Stub parity: seeded sysinfo, anomalies, and client-session state plus
  `system-stats`/`temperatures`/`stat.ap` fields on the seed gateway and AP so
  the offline stub backend returns plausible stats for every Wave C tool.

## [0.14.0] - 2026-06-12

### Added

- **IPv6 / dual-stack configuration tools (3 new Network tools).** IPv6 is
  modelled entirely inside the `/rest/networkconf` records the VLAN tools
  already read-modify-write, so these tools reuse `list_networks` /
  `update_network` (`PUT /rest/networkconf/<id>`) — no new endpoint. Every
  write reads the live record first, mutates only the supplied IPv6 keys, and
  writes the rest back unchanged. Mutating tools carry `dry_run=True` with a
  `before`/`after` diff.
  - `get_wan_ipv6` — read-only view of the WAN uplink IPv6 config:
    `wan_type_v6` (connection type), `ipv6_wan_delegation_type`,
    `wan_dhcpv6_pd_size_auto`/`wan_dhcpv6_pd_size`, `wan_ipv6_dns_preference`,
    `ipv6_setting_preference`. The read-before-write companion for
    `set_wan_ipv6`.
  - `set_wan_ipv6` — set the WAN IPv6 connection type
    (`disabled`/`dhcpv6`/`pppoe`/`static`), prefix delegation
    (`none`/`prefix-delegation`), PD size (48-64), and IPv6 DNS preference.
    Multi-WAN gateways select by `wan_name`. The `dry_run` output includes an
    explicit **blast-radius** note: changing the WAN IPv6 type re-establishes
    the WAN IPv6 session (IPv6 hosts briefly lose reachability; IPv4 is
    unaffected).
  - `set_lan_ipv6` — set a LAN/VLAN's IPv6 interface type
    (`none`/`pd`/`static`), Router Advertisements on/off, address-assignment
    mode (`slaac`/`dhcpv6`), and DHCPv6 DNS (auto or up to four explicit
    servers). Refuses a WAN target and points the caller at `set_wan_ipv6`.
- `list_networks` now surfaces each network's IPv6 state inline
  (`ipv6_interface_type`, `ipv6_ra_enabled`, `ipv6_client_address_assignment`)
  so callers see dual-stack status without a separate read.
- Stub parity: the seeded stub state now carries a WAN `networkconf` record
  and IPv6 keys on the LAN so the IPv6 tools return plausible state offline.

### Field surface (probed live, 2026-06-12)

- Probed a UCG-Fiber on UniFi Network 10.4.57 (Empire Access uplink, ASN
  40545). All WAN and LAN IPv6 keys above are present and writable on the
  `networkconf` records.

### Not added

- An IPv6-specific firewall tool. On this firmware the `/rest/firewallrule`
  records carry **no** IP-family/version field and only the `LAN_IN` ruleset
  is present, so IPv4 and IPv6 rules cannot be distinguished through this API
  surface. Follow-up gap: when IPv6 is enabled, IPv6 inbound hosts are not
  separately firewalled by the existing rule tools. Track separately before
  exposing global IPv6 to LAN clients.

## [0.13.0] - 2026-06-11

### Added

- **AP radio tuning and device management tools (5 new Network tools).**
  All write tools read the live device record first, mutate only the
  targeted radio's `radio_table` entry, and PUT the full table back
  (`PUT /rest/device/<id>`, the same endpoint `set_port_state` already
  uses) — untargeted radios and fields are preserved byte-for-byte.
  Every response includes the `before`/`after` values for the changed
  radio, and `dry_run=True` previews the exact diff without writing.
  - `get_device_radios` — read-only per-radio view: channel, width,
    `tx_power_mode`, `tx_power`, min-RSSI state, and the hardware
    `min_txpower`/`max_txpower` bounds. The read-before-write companion
    for the tools below.
  - `set_radio_tx_power` — per-radio transmit power mode
    (`auto`/`high`/`medium`/`low`/`custom` + exact dBm for custom,
    validated against the radio's supported range).
  - `set_radio_min_rssi` — enable/disable minimum RSSI per radio with a
    threshold in dBm, for kicking sticky clients toward a closer AP.
  - `set_radio_channel` — per-radio channel (`auto` or fixed) and/or
    channel width (20/40/80/160/240/320 MHz).
  - `rename_device` — set a device's display name.
  - Bands are addressed as `2g`/`5g`/`6g` (raw UniFi ids `ng`/`na`/`6e`
    also accepted).
- Backend seam: `get_device_by_mac` + `update_device` on the `Backend`
  protocol, both stub and real implementations.

### Not added

- A band-steering toggle was considered and dropped: probing a live
  UCG-Fiber (UniFi Network 10.4.57, AP fw 6.7.41) found no
  `bandsteering_mode` on device records and no per-WLAN steering toggle —
  recent firmware handles band assignment automatically.

## [0.12.0] - 2026-06-03

### Fixed

- **`list_alarms` uses the real alarm route on current firmware:**
  `GET /api/s/<site>/list/alarm?archived=<bool>` (the v0.11.0
  `POST /stat/alarm` form still 404'd against a live UCG-Fiber on
  UniFi Network 10.4.57), plus a defensive client-side `archived` filter.
- **`list_events` degrades gracefully on firmware with no event route:**
  `/stat/event` is genuinely absent on UCG-Fiber / Network 10.4.57 (404),
  so the client returns `[]` instead of erroring, and passes records
  through unchanged if a future firmware restores the route.
- `/health` echoes the running version in its JSON body.

## [0.11.0] - 2026-06-03

### Fixed

- **`list_alarms` and `list_events` no longer 404 on UniFi OS gateways.**
  On UniFi Network 9.x (UCG-Fiber, UDM) the legacy
  `GET /stat/event?_limit=...` and `GET /stat/alarm?archived=...&_limit=...`
  forms return HTTP 404 (`api.err.NotFound`). Both calls now `POST` to the
  same path with a JSON body `{"_limit", "_sort": "-time"}` (the modern
  controller contract, matching the existing `get_speedtest_results`
  migration). `list_alarms` over-fetches and filters the `archived` flag
  client-side, since server-side `archived` body filtering is inconsistent
  across firmware revisions. Alarm records surface the originating client
  MAC (`user`/`sta`), AP MAC (`ap`), `ssid`, `subsystem`, `msg`, and
  `time`/`datetime` fields unchanged.

### Changed

- **`/health` now returns a JSON `{"status": "ok", "version": ...}` body**
  instead of a bare `ok` string, so deploy checks can read the running
  version in one line (`curl .../health | jq .version`). The version is
  resolved from the installed package metadata
  (`importlib.metadata.version`), falling back to the in-tree
  `__version__` for source/editable runs. The Docker `HEALTHCHECK` gates
  on the HTTP 200 status code, not the body, so this change does not
  affect container health reporting.

## [0.10.1] - 2026-05-28

> **Fix-only release.** Routes controller-resolution errors through the
> standard ``err()`` envelope so they no longer escape as raw framework
> errors. No new tools.

### Fixed

- **Controller-resolution errors now return the ``err()`` envelope.**
  The dispatcher-layer resolution errors (``AccessNotAvailableError``,
  ``ProtectNotAvailableError``, ``UnknownControllerError``) are siblings
  of ``UniFiError``, not subclasses, so they slipped past each tool's
  ``except UniFiError`` guard and surfaced as raw framework errors. Most
  visible on the new Access module: enabling ``access`` without
  ``access_*`` config in real mode registered the tools but left the
  registry with no Access backend, so the first call raised an
  unhandled ``AccessNotAvailableError``.
- Added ``resolve_backend(registry, controller, kind)``, which
  translates the three resolution errors to ``UniFiError`` at the single
  seam every tool already guards. Migrated all Access, Network, and
  Protect tools to it; ``backup.py`` and ``drift.py`` now catch
  ``UniFiError`` instead of the raw resolution ``KeyError``.

### Changed

- An unknown / typo'd controller name on a Network or Protect tool now
  returns the ``err()`` envelope instead of raising. The
  no-silent-fallback guarantee is unchanged; ``test_multi_site`` was
  updated to pin the new contract.

## [0.10.0] - 2026-05-27

> **UniFi Access module: 18 read-only tools for doors, credentials,
> visitor passes, badge-scan events, and hub / reader hardware.**
> Brings the project to 86 total tools (57 Network + 11 Protect + 18
> Access). Access is opt-in, like Protect: set
> ``MCP_UNIFI_MODULES_ENABLED=network,protect,access`` to load all three.

### Added

- **UniFi Access module (opt-in).** New ``access`` module name for
  ``MCP_UNIFI_MODULES_ENABLED``. Ships 18 read-only tools across six
  surface areas:
  - Doors: ``list_doors``, ``get_door``, ``list_door_groups``
  - Policies: ``list_access_policies``, ``get_access_policy``
  - Credentials: ``list_credentials``, ``get_credential``,
    ``audit_expiring_credentials`` (composite read, surfaces
    credentials expiring in the next N days with computed
    ``days_until_expiry``).
  - Visitors: ``list_visitors``, ``get_visitor``
  - Events: ``list_access_events``, ``get_recent_access_events``,
    ``summarize_access_activity`` (composite, rolls up grants / denies
    by door and user), ``list_failed_access_attempts``
  - Devices: ``list_access_devices``, ``get_access_device``
  - System: ``get_access_system_info``, ``list_access_users``
- **New env vars** ``UNIFI_ACCESS_HOST``, ``UNIFI_ACCESS_API_KEY``,
  ``UNIFI_ACCESS_PORT`` (default ``12445``). The Access API key is
  **separate** from the Network key. Per-controller equivalents
  (``access_host``, ``access_api_key``, ``access_port``) are available
  in the YAML controllers file.
- **Stub mode coverage.** A fresh ``AccessStubState`` seeds 2 doors,
  1 door group, 1 access policy, 3 credentials (NFC / PIN / mobile),
  1 active visitor pass, 50 synthetic events spread across the last
  24 hours, 3 users, 1 hub, and 2 readers. Cross-references between
  users, credentials, doors, and devices are wired so the
  ``list_access_users`` ``credential_ids`` field actually points at
  real credentials.
- **Docs.** New ``reference/access`` page (full tool reference) and
  new ``guides/access-setup`` (dual-auth nuance, env-var wiring,
  common audit patterns).

### Changed

- **README hero.** Now reads ``Network + Protect + Access`` and the
  tool-count summary updated to ``57 + 11 + 18`` (86 total). Test
  count bumped from 537 → 619.

### Notes

- **Read-only by design.** UniFi Access mutations (door unlock,
  credential issuance, visitor pass create, policy update, device
  reboot) require a local username / password session, not the API
  key. v0.10 sticks with Option A (API-key reads only) so the
  v0.9.x API-key-first security posture stays intact. Write tools are
  deferred to a future v0.11+ gated by a separate explicit decision
  to introduce session-token auth alongside the API key.
- **Stub-mode-only development substrate.** Pete has no UniFi Access
  hardware. ``AccessClient`` is exercised end-to-end via
  ``respx``-mocked HTTP tests in ``tests/access/test_real_mode.py``.
  Hardware-validated real-mode integration lands in v0.10.x via a
  community tester or a future hardware acquisition.

## [0.9.1] - 2026-05-27

### Fixed

- **Auth env vars now work as documented.** v0.9.0 documented
  ``MCP_UNIFI_AUTH_TOKENS`` and ``MCP_UNIFI_AUTH_REQUIRED`` everywhere
  (README, guide, .env.example, Helm chart, error messages) but the
  underlying pydantic-settings fields had no prefix alias, so only the
  bare ``AUTH_TOKENS`` / ``AUTH_REQUIRED`` names worked. Added
  ``validation_alias`` to both fields. Both naming schemes now resolve
  to the same field; new deployments should use the documented
  ``MCP_UNIFI_AUTH_TOKENS``.

## [0.9.0] - 2026-05-27

> **Bearer-token authentication on HTTP transport, secure by default.**
> Anyone running v0.8.0 over streamable-http MUST either configure
> ``MCP_UNIFI_AUTH_TOKENS`` or explicitly opt out with
> ``MCP_UNIFI_AUTH_REQUIRED=false`` before upgrading. Stdio is unaffected.

### Added

- **HTTP transport authentication.** Streamable-HTTP requests are now
  authenticated via the ``Authorization: Bearer <token>`` header. Tokens
  are configured via the ``MCP_UNIFI_AUTH_TOKENS`` env var as a CSV of
  either bare tokens (auto-assigned client_id ``client-0``,
  ``client-1``, ...) or ``name:token`` pairs (named clients show up in
  the audit log by name). Backed by FastMCP's ``StaticTokenVerifier``.
- **Per-call authenticated client_id in the audit log.** Every entry now
  carries a ``client_id`` field. Set to the authenticated client's id on
  HTTP transport, ``null`` on stdio or when auth is disabled. Old logs
  without the field continue to parse via the dataclass default — no
  schema bump.

### Changed

- **BREAKING (HTTP transport only).** ``build_server`` raises at startup
  if ``mcp_transport=streamable-http`` and ``auth_required=true`` (the
  default) and no tokens are configured. Migration: generate a token
  with ``openssl rand -hex 32``, set ``MCP_UNIFI_AUTH_TOKENS=<token>``,
  update each client config to send the ``Authorization`` header. Stdio
  transport is unaffected — the parent process owns the security
  boundary, so layering bearer auth there would be theatre.
- New env vars: ``MCP_UNIFI_AUTH_TOKENS`` (default empty),
  ``MCP_UNIFI_AUTH_REQUIRED`` (default ``true``). The latter is an
  escape hatch for single-host trusted-boundary deployments; flipping
  it logs a loud WARNING at boot.

### Internal

- ``Settings.auth_token_map`` parses the CSV into the dict shape FastMCP
  expects, rejecting duplicate tokens and empty values at config-load
  time rather than first-request time.
- ``@audited`` decorator pulls ``client_id`` from
  ``fastmcp.server.dependencies.get_access_token()`` per call. Falls
  back to ``None`` outside an HTTP request scope (stdio, direct
  ``server.call_tool`` invocations, tests).

## [0.8.0] - 2026-05-26

> **UCG-Fiber security/VPN coverage.** Seven new Network tools for
> Threat Management (IDS/IPS), Honeypot, and Teleport VPN, plus a fix
> for the long-standing sparse-record bug in ``get_speedtest_results``.

### Added

- **Threat Management (IDS/IPS).** Two tools that wrap the controller's
  ``ips`` setting record.
  - ``get_threat_management`` — current state: enabled flag, mode
    (``off`` / ``ids`` / ``ips``), active signature categories, enabled
    networks, plus adjacent feature flags (endpoint scanning, ad
    blocking, DNS filtering, honeypot).
  - ``set_threat_management(enabled, mode, signature_categories, ...)``
    — partial-update via ``POST /set/setting/ips``. ``enabled=False``
    forces ``mode=off``; supplying ``signature_categories`` replaces
    the active list wholesale.
- **Honeypot.** Three tools backed by the ``honeypot`` list inside the
  ``ips`` setting (honeypots are not a dedicated REST collection on
  UniFi Network 9.x).
  - ``list_honeypots`` — current entries + global enabled flag, with
    network-name lookup for friendly output.
  - ``create_honeypot(network_id, ip)`` — validates the IPv4, refuses
    duplicates, appends to the list, flips ``honeypot_enabled=true``.
  - ``delete_honeypot(id)`` — preview-then-confirm (matches the v0.7.0
    destructive contract); rewrites the list with the entry removed.
- **Teleport VPN.** Two tools that wrap the local controller's
  ``teleport`` setting. The client roster and invitation lifecycle
  are not exposed via the local Network API on UCG-Fiber fw
  5.1.12.33296 — Apoc should treat those operations as UI-only.
  - ``get_teleport_config`` — current state plus a list of underlying
    wireguard-server networks and a ``clients_via_local_api=false``
    indicator so callers don't ask for a roster here.
  - ``set_teleport_enabled(enabled)`` — toggle the listener.

### Fixed

- **``get_speedtest_results`` returned sparse records.** On UCG-Fiber
  fw 5.1.12.33296 the legacy ``GET
  /stat/report/archive.speedtest?_limit=...`` returns records that
  only carry ``_id`` / ``oid`` / ``o`` — the metric fields are not
  projected. The client now issues a ``POST`` with an ``attrs``
  projection list. The controller returns ``xput_upload`` rather than
  the older ``xput_up``; the client normalises both fields onto the
  result so existing callers see the documented shape regardless of
  the controller version.

### Internal

- New per-key setting access on the client + backend:
  ``UniFiClient.get_setting(key)`` and ``UniFiClient.set_setting(key,
  patch)`` wrap ``GET /rest/setting/<key>`` and ``POST
  /set/setting/<key>``. Stub state gains an in-memory ``settings``
  dict seeded with realistic ``ips`` and ``teleport`` records.

## [0.7.0] - 2026-05-25

> **Breaking: preview-then-confirm for destructive Network tools.** All six
> ``delete_*`` tools in the Network module now return a preview envelope
> with a single-use token instead of mutating the controller directly. A
> new ``confirm_destructive_action(token)`` tool runs the queued delete.
> Tokens expire 5 minutes after issuance. Existing flows that call
> ``delete_firewall_rule(rule_id="...")`` and expect immediate deletion
> MUST be updated to follow the preview with a confirm call. Migration
> below.

### Breaking changes

- **Six ``delete_*`` tools changed contract.** ``delete_firewall_rule``,
  ``delete_vlan``, ``delete_wlan``, ``delete_port_profile``,
  ``delete_port_forward``, and ``delete_static_dhcp_lease`` no longer
  delete on their own. They:
  1. Resolve the target via the existing list lookup.
  2. Generate a UUID4 token, store a :class:`PendingAction` in an
     in-process registry with a 5-minute TTL.
  3. Return a preview envelope:

     .. code-block:: json

        {
          "preview": true,
          "action": "delete_firewall_rule",
          "controller": "default",
          "resource": {"_id": "abc", "name": "..."},
          "token": "<uuid4>",
          "expires_at": "<iso8601>",
          "confirm_with": "confirm_destructive_action"
        }

  Callers commit the change by passing ``token`` back to
  ``confirm_destructive_action(token=...)``. ``dry_run=True`` still works
  and still returns the legacy ``{"dry_run": true, "would_delete": ...}``
  envelope (no token, no commit step possible) for informational use.

- **The "missing record" error envelope changed.** Pre-0.7.0 the six
  ``delete_*`` tools returned ``{"deleted": false, "<id>_id": "..."}``
  when the target didn't exist. Post-0.7.0 they return the standard error
  envelope ``{"error": "... not found", "stub_mode": bool}`` from the
  preview lookup. Callers branching on ``result["deleted"]`` need to
  branch on ``result.get("error")`` instead.

### Added

- **``confirm_destructive_action(token: str)`` tool.** Resolves a
  preview token, runs the queued executor, removes the token from the
  registry, returns the standard delete-tool result. Unknown, used, or
  expired tokens return the standard error envelope.
- **``src/mcp_unifi/modules/network/_pending.py``** holds the
  :class:`PendingAction` dataclass and :class:`PendingActionsRegistry`.
  Module-global, lazily swept on every access. ``reset_pending_actions``
  is the test-isolation seam.
- **``scripts/generate_tool_manifest.py``** introspects the FastMCP
  registration and emits one MDX file per tool under
  ``docs/site/src/content/docs/tools/``. Re-runs are deterministic. A
  pre-commit hook keeps the docs in sync with the registered surface.
- **``.pre-commit-config.yaml``** wires up the manifest generator, ruff
  (lint + format), and mypy strict. Run ``pre-commit install`` once per
  clone.

### Audit log

- Two events per destructive action now: the preview call (action name +
  resolved resource ID), and the confirm call
  (``confirm_destructive_action`` with the token). A future replay tool
  can stitch the two halves together via the shared token.

### Migration

Old flow:

.. code-block:: python

    delete_firewall_rule(rule_id="abc")

New flow (two calls):

.. code-block:: python

    preview = delete_firewall_rule(rule_id="abc")
    confirm_destructive_action(token=preview["token"])

For a single-step UX, agents (e.g. Apoc) should chain preview → confirm
inside their handler. ``dry_run=True`` is unchanged and still returns
the legacy preview shape with no token.

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
