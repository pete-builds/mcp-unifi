# 0009. Zone policy writes use the Integration API only, with no private fallback

**Status:** Accepted. Not yet exercised against a zone-based console; see
"Not established".

## Context

The server could read Zone-Based Firewall policies and zones (private v2
`/firewall-policies` and `/firewall/zone`) but every firewall write it made was a
legacy rule under `/rest/firewallrule`. On a site that has migrated to zones,
that leaves no way to change the firewall, and the three composites that create
an isolation or allow rule (`create_iot_network`, `create_guest_network`,
`provision_homelab_service`) write rules into rulesets the site no longer uses.

Two surfaces could carry zone policy writes:

- The **official Integration API**. The UniFi Network 10.6.106 reference
  publishes `POST`, `PUT`, `PATCH` and `DELETE` on
  `/v1/sites/{siteId}/firewall/policies`, plus zone CRUD and policy ordering,
  with full request schemas. Read 2026-10-18 from the scrape in
  KallistoX/mcp-unifi-applications (`docs/network/*.json`, scraped 2026-10-12,
  `version: 10.6.106`), whose `sourceUrl` fields point at
  developer.ui.com/network/v10.6.106/.
- The **private v2 API** the UniFi app itself uses. Ubiquiti does not document
  its write payloads. Third-party servers write them anyway (sirkirby's
  unifi-network-mcp is built on zone policies), from shapes reverse-engineered
  off the UniFi app; this project has not verified any of them.

The console this server runs against (UCG-Fiber, Network 10.6.106) has not
migrated. Its v1 `firewall/zones` and `firewall/policies` answer 400
`api.firewall.zone-based-firewall-not-configured` (ADR 0005's 2026-10-17
re-probe), and its private v2 lists are empty. Neither surface can be probed for
write shapes without migrating the site, which is a production firewall change.

## Decision

Zone policy create, update and delete go through the Integration API and nowhere
else.

- `clients/zone_policy.py` builds bodies from the published schema: a zone plus
  an optional `NETWORK`, `IP_ADDRESS` or `PORT` traffic filter per side,
  `ipProtocolScope` for all, TCP, UDP, TCP+UDP or ICMP, and `action` with
  `allowReturnTraffic` on ALLOW. Tests pin the top-level field set against the
  reference's own lists.
- `IntegrationWrites` gains the HTTP calls. A 4xx is **not** replayed anywhere:
  it reaches the caller with the console's own `message`, which ADR 0008 found
  names the field the console wanted.
- New tools `create_firewall_policy`, `update_firewall_policy` and
  `delete_firewall_policy` address policies by v1 id or exact name, zones by
  name or v1 id, and networks by private `_id` translated through `external_id`
  (the mapping ADR 0008 verified for every network). Only `USER_DEFINED`
  policies can be edited or deleted. Delete goes through the confirm token.
- The firewall model is read per call from v1 `firewall/zones`: 200 is
  zone-based, the not-configured 400 is legacy, 404 is a console without the
  route. It is not cached, since a site can migrate while the server runs.
- The composites check the model before their first write. On a zone-based site
  they create a zone policy matched by address (isolation: BLOCK new subnet to
  main LAN subnet; service: ALLOW `Internal` to the service IP on its TCP
  ports), and roll it back like any other step. On a legacy site, or under
  `write_api: private`, they behave exactly as before.
- `restore_config` skips a backup's legacy `firewall_rules` on a zone-based site
  and says how many it skipped.

## Alternatives considered

**Hybrid with a private fallback, as ADR 0008 does for networks and WLANs.**
Rejected. ADR 0008's fallback replays a payload whose private shape this
server has exercised live for years. Here the private shape is known only
second-hand, from another project's reverse engineering: a fallback would mean
writing an unverified payload to a production firewall at exactly the moment
the documented one was refused. A refusal surfaced verbatim is the safer
failure.

**Private v2 only.** Rejected for the same reason, without even the
documentation the v1 route has.

**Wait until the site migrates, then build against live shapes.** Rejected as
the order of work. The live write test needs a release with the tools in it;
building first and testing on the day of migration keeps the window where the
firewall cannot be changed through this server to hours, not a release cycle.

**Make `create_firewall_rule` translate legacy rules into zone policies.**
Rejected. Rulesets and zone pairs do not map one to one (`LAN_IN` from one
network to another may be intra-zone or cross-zone depending on zone
membership), so a silent translation would guess at intent. The composites can
translate because each one knows its own intent.

## Consequences and accepted costs

- **The shapes are documented, not verified.** ADR 0008 found the same reference
  wrong about five WLAN fields and five network fields. Expect the first live
  write to be refused for a field the schema marks optional. The error names
  it; the fix is a builder change plus a test.
- **The scrape is lossy in one place.** The reference shows `PORT_NUMBER_RANGE`
  as `start`/`stop` integers on one traffic-filter variant and as a `value`
  string on another. The builder uses `start`/`stop`. Unverified.
- **Zone membership of a new network** is read from the v1 zone list right
  after the network is created. If the console has not placed it yet, the
  composite uses `Internal` and writes that into the policy description.
- **`write_api: private` disables zone writes entirely,** because there is no
  private path. On a zone-based site under `private`, the composites keep
  writing legacy rules, which is the pre-0009 behavior.
- Zones, policy ordering, and zone policies in `backup_config` are not covered.

## Not established

No request in this record has been sent to a zone-based console. The tests run
against a stub that implements the documented contract and against mocked HTTP.
The live evidence ADR 0008 rests on (probe, guarded create/update/delete, read
back on both surfaces) is the reversal condition below, and it is owed.

## Reversal condition

Add a private fallback for a specific operation once its private v2 payload has
been captured from the UniFi app on a zone-based site and replayed successfully
in a guarded test. Drop the Integration API path for an operation if a live
write through it applies a change that differs from the body sent (for example
a policy landing in a different zone pair), which a refusal does not count as.
