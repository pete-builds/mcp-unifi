# Plan: Zone-Based Firewall writes

**Date:** 2026-10-18
**Status:** Steps 1 and 2 in PR; step 3 waits on the operator.
**Decision record:** [ADR 0009](../decisions/0009-zone-policy-writes-use-the-integration-api-only.md)

## Why

UniFi is moving every site from legacy firewall rules (`LAN_IN`, `WAN_IN` and
the other rulesets) to the Zone-Based Firewall. This server can read zone
policies and zones, but every firewall write it makes is a legacy rule:
`create_firewall_rule`, `update_firewall_rule`, `delete_firewall_rule`, the
three composites that create one (`create_iot_network`, `create_guest_network`,
`provision_homelab_service`), and `restore_config`. On a site that has
migrated, the server cannot change the firewall at all. That makes it the thing
holding a site back from migrating.

The official Integration API on Network 10.6.106 publishes create, update,
patch and delete routes for firewall policies and zones. The private v2 API the
UI uses has the same objects, but its write payloads are undocumented.

## Steps

### 1. Clear the queue (operator)

- #195 (TLS pin read once) is reviewed and ready to merge.
- #193 and #164 are housekeeping drafts for Mouse to decide.

### 2. Build zone policy writes (this PR)

- New tools: `create_firewall_policy`, `update_firewall_policy`,
  `delete_firewall_policy` (preview token, like every other delete).
- Writes go through the Integration API only. No private fallback, because the
  private payload shape is not documented and cannot be probed on a site with
  no zones. ADR 0009 records the reasoning.
- The three composites detect a zone-based site and create a zone policy in
  place of the legacy rule, with the same rollback.
- `restore_config` stops replaying legacy firewall rules onto a zone-based
  site and reports them as skipped.
- Legacy sites see no change: detection answers "legacy" and every path runs
  exactly as before. `write_api: private` also keeps the old behavior.

### 3. Migrate and test live (operator present)

This is a firewall change on a production network, so it runs only with the
operator watching and after an explicit go-ahead.

1. Release and deploy the version from step 2.
2. `backup_config`, and keep the envelope off the controller.
3. Migrate the site to the Zone-Based Firewall in the UniFi app.
4. Re-run `scripts/probe_integration_api.py`: `firewall/zones` and
   `firewall/policies` should now answer 200.
5. Compare every legacy rule against the converted policies, then test the
   segmentation that matters: IoT cannot reach TRUSTED or MGMT, guest cannot
   reach anything internal, and the two single-host allows (Plex, the weather
   station ingest) still pass.
6. Guarded write test through the deployed server, the same evidence standard
   as ADR 0008: create a disabled throwaway policy, update it, delete it, and
   confirm each step on both the Integration API and the private v2 list.
7. Record which fields the console actually required. ADR 0008 found five
   undocumented required fields on WLAN create; expect the same here.

## Not in scope

- Zone create, update and delete. The default zones cover the composites; a
  zone tool can follow once step 3 shows what the defaults look like live.
- Policy ordering (`firewall/policies/ordering`).
- Backing up and restoring zone policies in `backup_config`. That needs the
  live shapes from step 3 first.
- Moving legacy rule writes anywhere. They stay on the private API (ADR 0005).

## Known risks

- **Nothing in step 2 has touched a real zone-based console.** The payloads
  follow the published 10.6.106 reference, which was wrong about required
  fields for networks and WLANs. A 4xx from the console comes back to the
  caller with the console's own message, so a missing field is visible, not
  silent.
- **Zone membership of a brand new network** is assumed to show up in the
  zone list immediately. If it does not, the composites fall back to the zone
  named `Internal` and say so in the policy description.
