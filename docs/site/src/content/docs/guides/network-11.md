---
draft: false
title: UniFi Network 11
description: What changed in UniFi Network 11 and how mcp-unifi behaves on it.
---

UniFi Network 11.0.97 moved every site to the Zone-Based Firewall automatically, with no opt-out. On such a site the legacy rule list (`list_firewall_rules`) is empty, so the legacy rule tools have nothing to act on. Use `list_firewall_zones`, `list_firewall_policies` and the `*_firewall_policy` tools instead. Consoles older than 11.0.97 can still hold legacy rules, and the legacy tools still work there.

- **Firewall tools (from 0.31.0).** `create_firewall_rule`, `update_firewall_rule` and `delete_firewall_rule` refuse on a Zone-Based Firewall site and point at `create_firewall_policy`, `update_firewall_policy` and `delete_firewall_policy`.
- **Ids are UUIDs.** Record `_id` values are UUID strings. Networks and WLANs keep the old 24-character ObjectId as `legacy_id`. Some older static DHCP leases still store a network's `legacy_id` in `network_id`.
- **Integration API timeout (from 0.31.0).** Integration API writes wait up to 60 seconds, because consoles before 11.1.58 can stall such requests for up to 40 seconds.
- **Event log.** `list_events` reads the v2 system log and works on Network 11.0.99. `list_alarms` reads the v2 critical log too, but it has not been checked on Network 11.
