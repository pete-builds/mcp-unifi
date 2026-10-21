# 0008. Network and WLAN writes use the Integration API where they map onto it

**Status:** Accepted. Supersedes [0005](0005-writes-stay-on-the-private-network-api.md)
for network and WLAN writes; 0005 still governs every other write.

## Context

[ADR 0005](0005-writes-stay-on-the-private-network-api.md) kept every write on the
private Network API because the official Integration API
(`/proxy/network/integration/v1`) exposed only devices and clients on Network
10.4.57. Its reversal condition was a live re-probe, per capability.

On 2026-10-17, against a UCG-Fiber running Network 10.6.106:

- `scripts/probe_integration_api.py` found networks and WiFi broadcasts served with
  live data (recorded in 0005's re-probe section).
- A guarded write test created, renamed and deleted a throwaway network and WLAN
  through v1. Every step read back correctly on both surfaces, and the private
  API saw each v1 write immediately. Every device took a provision push; none
  rebooted and no client dropped.
- The two surfaces share one identity: every private `networkconf` and `wlanconf`
  record carries an `external_id` equal to its v1 UUID, for every network and WLAN
  on the console.
- The published schema is wrong about what is required. A WLAN create is refused
  without `advertiseDeviceName`, `arpProxyEnabled`, `broadcastingFrequenciesGHz`,
  `bssTransitionEnabled` and `securityConfiguration.fastRoamingEnabled`; a network
  create without `internetAccessEnabled`, `cellularBackupEnabled`,
  `isolationEnabled`, and on its DHCP block `leaseTimeSeconds` and
  `pingConflictDetectionEnabled`. developer.ui.com marks all of them optional.
- v1 has no guest-network concept (a `purpose: guest` network reads back exactly
  like a corporate one), and no route at all for port forwards, static routes,
  DHCP reservations, port profiles or legacy firewall rules.

## Decision

Route network and WLAN create, update and delete through the Integration API when,
and only when, the private-shape payload maps onto it exactly. Everything else
stays on the private API.

- `src/mcp_unifi/clients/integration_translate.py` holds the map. Each function
  returns the v1 body, or `None` for anything without an exact equivalent: guest
  networks, IPv6, DHCP DNS overrides, and WLANs that are guest, enterprise, open,
  WPA3, 6 GHz, scheduled, or bound to anything other than the default AP group.
  Field shapes and defaults come from live readbacks, not from the published
  schema.
- `src/mcp_unifi/clients/integration.py` (`IntegrationWrites`) sits behind
  `RealBackend`. It resolves a private `_id` to its v1 id through `external_id`,
  sends the write, then re-reads the private record and returns that, so every
  tool's inputs and outputs are unchanged and callers cannot tell which surface
  ran.
- A v1 **4xx** falls back to the private API: the console refused and changed
  nothing. A **404 on a collection** also marks it absent for the process, which
  is how older firmware without the route keeps working. A **5xx, timeout, or
  dropped connection never falls back**: the write may have applied, and replaying
  it on the other surface could apply it twice.
- Per controller, `write_api: auto | private` (env `UNIFI_WRITE_API`), default
  `auto`. Each v1 write logs at INFO with `write_api: integration` and the v1 id;
  each fallback logs a WARNING with the console's status, code and message.

## Alternatives considered

**Keep every write private (ADR 0005 unchanged).** Rejected. 0005's own reversal
condition is met for exactly these two capabilities, and the private surface has
already broken a route this server depended on without notice.

**Migrate every write.** Rejected for the reason 0005 gave: v1 has no route for
most of what this server writes, and no guest semantics.

**Route by tool rather than by payload** (for example, `create_vlan` always on v1).
Rejected. One tool's payloads span both sides of the line: `create_vlan` with
`purpose="guest"` cannot be expressed on v1, and composites, backup restore and
`update_vlan` pass arbitrary private keys. Deciding per payload is the only rule
that never silently drops a field.

**Fall back on any v1 error, 5xx included.** Rejected. A 5xx or a timeout does not
mean nothing happened; replaying a create on the private API could leave two
networks on one VLAN. The retry layer already refuses to replay writes for the
same reason.

**Default to `private` and make v1 opt-in.** Rejected. The fallback means a console
without the route, or one that refuses a payload, behaves exactly as before, so
`auto` cannot narrow a working install; ADR 0007's opt-in rule is for hardening
that can. The opt-out exists for anyone who wants the old behavior regardless.

## Consequences and accepted costs

- **Two code paths for the same tools,** and a rule about which one runs that
  depends on the payload, not the tool. The translation module is the single
  place that rule lives, and it is tested case by case.
- **More requests per write.** A v1 write adds a site lookup (cached per process),
  a private list read to resolve the id, a v1 readback before an update, and a
  private list read to return the record. On a home console this is a few tens of
  milliseconds; it is not free.
- **The fallback can hide a v1 regression.** If a firmware update starts refusing a
  v1 payload, writes keep working on the private API and the only signal is the
  WARNING. That is the intended trade, availability over purity, but it means the
  log is where to look.
- **The schema is not trustworthy.** Required fields were found by the console
  refusing requests, on one firmware version and one hardware model. A future
  firmware can demand more; the 4xx fallback absorbs that, and the WARNING names
  the field.
- Tested live on one UCG-Fiber, Network 10.6.106. Nothing guarantees another
  console behaves the same way.

## Reversal condition

Move a further capability onto v1 when `scripts/probe_integration_api.py` shows its
route on current firmware and a guarded live write test passes, the same evidence
this record rests on. Extend the translation rather than adding a second router.

Revert to `write_api: private` as the default if v1 network or WLAN writes are seen
to apply a change that differs from what the same private payload would have
applied, for example a WLAN broadcasting on APs outside its intended group. A
fallback WARNING alone is not that signal; a wrong change is.
