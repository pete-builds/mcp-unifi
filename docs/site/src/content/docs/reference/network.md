---
draft: false
title: Network Tools
description: Reference for the Network module tool surface.
---

The Network module is loaded by default (`MCP_UNIFI_MODULES_ENABLED=network`). It covers devices, networks/VLANs, WLANs, firewall rules, switch port profiles, per-client commands, static DHCP leases, port forwards, observability, plus composites with rollback and config drift / backup utilities. See the [Tool Manifest](/mcp-unifi/tools/) for the always-current per-module count.

Every tool accepts an optional `controller: str = "default"` parameter that names which UniFi controller to target. Every destructive tool also accepts `dry_run: bool = False`; setting it to `True` returns the predicted change set without writing to the controller.

Every tool returns a JSON string. Errors are returned as `{"error": "...", "stub_mode": bool}` so the MCP loop never crashes on a controller hiccup.

## Devices

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_devices` | read | — | List adopted gateways, APs, and switches with state, uptime, and per-radio info. |
| `restart_device` | write | yes | Restart an adopted device by MAC. |
| `locate_device` | write | yes | Toggle the LED locate beacon on a device. |
| `set_port_state` | write | yes | Override one switch port (PoE, enable, profile). Preserves other port overrides in real mode. |

## Networks / VLANs

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_networks` | read | — | List all configured networks/VLANs (subnet, DHCP range, VLAN ID). |
| `create_vlan` | write | yes | Create a new VLAN-tagged network. |
| `update_vlan` | write | yes | Patch fields on an existing VLAN. |
| `delete_vlan` | write | yes | Delete a VLAN. |

## WLANs

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_wlans` | read | — | List all WiFi SSIDs. |
| `create_wlan` | write | yes | Create a new SSID bound to a specific VLAN. |
| `update_wlan` | write | yes | Patch fields on an existing SSID. |
| `delete_wlan` | write | yes | Delete a WiFi SSID. |

## Firewall

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_firewall_rules` | read | — | List all firewall rules. |
| `create_firewall_rule` | write | yes | Create a firewall rule. |
| `update_firewall_rule` | write | yes | Patch fields on an existing firewall rule. |
| `delete_firewall_rule` | write | yes | Delete a firewall rule. |

## Port Profiles

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_port_profiles` | read | — | List switch port profiles (PoE mode, native VLAN, forwarding). |
| `create_port_profile` | write | yes | Create a switch port profile. |
| `update_port_profile` | write | yes | Patch fields on a port profile. |
| `delete_port_profile` | write | yes | Delete a port profile. |

## Clients

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_clients` | read | — | List connected wireless and wired clients (MAC, hostname, IP, signal, AP or switch port, uptime). |
| `block_client` | write | yes | Block a client by MAC. |
| `unblock_client` | write | yes | Unblock a previously-blocked client. |
| `reconnect_client` | write | yes | Force a client to reconnect (kick-sta). |
| `update_clients` | write | yes | Set or clear the display name and note of up to 100 clients by MAC. Cosmetic only: no IP reservation. |

`update_clients` takes a list of `{mac, name, note}` items. A field left out (or sent as `null`) is kept, `""` clears it, and only fields that differ are sent, as a partial `PUT /rest/user/{_id}`. The controller's `noted` flag is updated alongside when it has to change. Each MAC gets its own `status` (`updated`, `unchanged`, `not_found` or `failed`), and one failure does not stop the rest. Clearing through this endpoint is not yet verified on real hardware.

```python
update_clients(updates=[{"mac": "aa:bb:cc:00:00:02", "name": "Pete's iPhone"}, {"mac": "aa:bb:cc:00:00:04", "note": ""}], dry_run=True)
```

## DHCP

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_dhcp_leases` | read | — | List static DHCP reservations. |
| `create_static_dhcp_lease` | write | yes | Reserve a fixed IP for a new MAC. |
| `update_static_dhcp_lease` | write | yes | Convert/update an existing client to a fixed IP (use when MAC is already known). `network_id` is optional; to rename without a reservation use `update_clients`. |
| `delete_static_dhcp_lease` | write | yes | Delete a static reservation. |

## Port Forwards

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_port_forwards` | read | — | List all port-forward (DNAT) rules. |
| `create_port_forward` | write | yes | Create a port-forward rule. |
| `update_port_forward` | write | yes | Patch a port-forward rule. |
| `delete_port_forward` | write | yes | Delete a port-forward rule. |

## Observability

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `get_site_health` | read | — | Per-subsystem health (wan, lan, wlan, www, vpn). |
| `get_wan_status` | read | — | WAN subsystem record (link, ISP, public IP, throughput, latency). |
| `list_events` | read | — | Controller event log for the last N hours, from the v2 system log (`system-log/all`). |
| `list_alarms` | read | — | Critical system log (`system-log/critical`); archived alarms on legacy controllers only. |
| `list_threat_detections` | read | — | IDS/IPS detections and blocks (`traffic-flows` + `system-log/threat-alert`), filterable by client IP or MAC. |
| `trigger_speedtest` | write | — | Kick off a UniFi WAN speed test. (Read-side-effects only; no config mutation.) |
| `get_speedtest_results` | read | — | Recent speed-test results, newest first. |
| `list_top_talkers` | read | — | Connected clients ranked by bytes moved since each connected. |

## Diagnose

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `diagnose_site` | read | — | One-call site diagnosis: a verdict, rule-based findings with their evidence, what could not be checked, and which tool to call next. |

`diagnose_site` is the first call for "is my network healthy?". It makes five reads (`list_devices`, `get_site_health`, `list_clients`, `list_alarms`, `list_threat_detections`), runs fixed rules over them, and returns findings. There is no AI inside it: the same controller state always gives the same answer, byte for byte, and the agent calling it does the reasoning. The design and its trade-offs are in [ADR 0010](https://github.com/pete-builds/mcp-unifi/blob/main/docs/decisions/0010-site-diagnosis-is-deterministic-rules-over-existing-reads.md).

**How to read the answer.**

- `verdict` is `critical` when any finding is critical; `unknown` when a rule that can find a critical problem (`device.offline`, `wan.down`, `health.subsystem_not_ok`) could not run over everything it needs; `degraded` when there is a warning; otherwise `healthy`. Info findings never change it.
- A diagnosis is never `healthy` when any of the five reads failed, one of the two IPS routes behind `list_threat_detections` failed, or any rule raised: what would have been `healthy` is `unknown`. The one exception is a route this firmware does not have (the client raises `UniFiUnsupportedError`, which `list_alarms` and `list_threat_detections` can): those rules are listed under `not_evaluated` as "not supported on this controller", the check carries `unsupported: true`, and the site can still be `healthy`.
- A read that says it was cut short (more IPS detections or alarm entries than were returned, an IPS route capped at the scan limit, or a window not read to the end) is listed as a `partial` gap with the counts, and its findings say the counts are lower bounds. A failed IPS route is not "cut short": the IPS envelope cannot say whether it was missing on this firmware or broken, so it blocks `healthy`.
- Rows a read returns that are not objects are skipped and counted (`skipped_rows` in `checks`), and every rule reading that source lists a `partial` gap; for devices and site health that means `unknown`, never `healthy`.
- An adopted device left unplugged keeps the site `critical` (`device.offline`) until it is reconnected or forgotten in the controller.
- Each finding keeps `observed` (values read from the controller, each with the tool it came from) apart from `inferred` (the rule's conclusion). `next` names tools to call with their arguments, always including the `controller` the diagnosis ran on.
- `not_evaluated` lists every rule that did not run (`scope: "rule"`) or ran over only some devices or subsystems (`scope: "partial"`), with the reason. `rules_evaluated` lists the rest. A failed read is never read as a clean one: it appears in `checks` with its error, and the top-level `next` points at `get_console_health`.
- Every string that comes from the controller (device names, models and types, firmware versions, alarm keys, IPS actions and categories) is treated as untrusted: it appears only in `subject` and `observed`, with control characters stripped and capped at 80 characters, never in `summary`, `inferred`, `limitations` or `not_evaluated`. A rule that raises is reported by its exception class only.
- At most 10 findings per rule; any more are counted in `truncated`. `thresholds` echoes every threshold used. They are this project's conservative defaults, not Ubiquiti guidance.

**Rules.** The ids are stable and safe to grade against.

| Rule id | Severity | Reads | Fires when |
|---|---|---|---|
| `device.offline` | critical | `list_devices` | An adopted device reports `state` 0 (disconnected). |
| `device.not_connected` | warning | `list_devices` | An adopted device reports any `state` other than 0 or 1 (upgrading, provisioning, heartbeat missed...). |
| `device.high_cpu` | warning | `list_devices` | A connected device's `system-stats.cpu` is above 90. |
| `device.high_memory` | warning | `list_devices` | A connected device's `system-stats.mem` is above 90. |
| `device.upgradable` | info | `list_devices` | The controller flags a device `upgradable`. Not evaluated when no record carries the flag. |
| `wan.down` | critical | `get_site_health` | The `wan` subsystem status is `error`. |
| `health.subsystem_not_ok` | critical, warning or info | `get_site_health` | A `wan`, `www`, `lan` or `wlan` status is not `ok`: `error` is critical, `warning` is a warning, anything else is info. `vpn` is not evaluated, because a site with no VPN reports it as `warning`. |
| `wifi.weak_signal_clients` | warning | `list_clients` | An AP has 3 or more wireless clients below -75 dBm. |
| `alarms.active` | warning | `list_alarms` | The critical log holds entries from the last 24 hours, one finding per alarm key. |
| `threats.detected` | warning or info | `list_threat_detections` | Threat Management recorded detections in the last 24 hours. Blocked ones are info; the rest are a warning. |

**Worked example.** The stub site with its access point disconnected (seed alarms and IPS rows cleared), `thresholds` omitted:

```json
{
  "diagnosis": "site",
  "controller": "default",
  "stub_mode": true,
  "verdict": "critical",
  "summary": "1 critical and 0 warning finding(s). 3 rule(s) not fully evaluated.",
  "findings": [
    {
      "id": "device.offline",
      "severity": "critical",
      "subject": { "type": "device", "mac": "f4:e2:c6:00:00:02", "name": "U7 Pro - Living Room", "device_type": "uap" },
      "observed": [{ "fact": "state=0", "source": "list_devices" }],
      "inferred": "The controller reports this adopted device as disconnected.",
      "confidence": "high",
      "limitations": [],
      "next": [
        { "tool": "get_device_stats", "args": { "controller": "default", "mac": "f4:e2:c6:00:00:02" } },
        { "tool": "list_events", "args": { "controller": "default", "hours": 24 } }
      ]
    }
  ],
  "truncated": {},
  "not_evaluated": [
    { "rule": "device.high_cpu", "scope": "partial", "reason": "1 of 2 connected devices report no system-stats cpu" },
    { "rule": "device.high_memory", "scope": "partial", "reason": "1 of 2 connected devices report no system-stats mem" },
    { "rule": "device.upgradable", "scope": "rule", "reason": "no device record carries an upgradable flag" }
  ],
  "rules_evaluated": ["alarms.active", "device.high_cpu", "device.high_memory", "device.not_connected", "device.offline", "health.subsystem_not_ok", "threats.detected", "wan.down", "wifi.weak_signal_clients"],
  "checks": [
    { "source": "list_devices", "ok": true, "records": 3 },
    { "source": "get_site_health", "ok": true, "records": 5 },
    { "source": "list_clients", "ok": true, "records": 4 },
    { "source": "list_alarms", "ok": true, "records": 0 },
    { "source": "list_threat_detections", "ok": true, "records": 0 }
  ],
  "next": []
}
```

Read it as: one access point is down, which is why the verdict is `critical`; the agent's next calls are `get_device_stats` for that MAC and `list_events` for when it dropped. The switch reports no CPU or memory figures and no device carries an upgrade flag, so those checks say so instead of passing silently.

## Composites (with rollback)

These tools chain primitive operations into one call and roll back on partial failure. The response includes `partial` and `rolled_back` keys describing exactly what was undone.

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `create_iot_network` | write | yes | VLAN + SSID + isolation rule in one call. |
| `create_guest_network` | write | yes | Guest VLAN + guest SSID + isolation rule. |
| `provision_homelab_service` | write | yes | Static lease + LAN_LOCAL accept rule + (optional) port forwards. |
| `quarantine_client` | write | yes | Block client + structured warning log carrying the reason. |
| `audit_open_ports` | read | — | Read-only review of WAN-facing exposure (active port forwards + non-boilerplate WAN accept rules). |

## Drift, backup, restore

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `audit_network_drift` | read | — | Compare current controller state to a declared YAML spec; returns structured diff. Anything in the spec it cannot compare (an unknown section or key) is listed in `not_compared`, and `in_sync` is `true` only when that list is empty too. A name the controller holds twice is reported as a duplicate. |
| `backup_config` | read | — | Snapshot controller state into a versioned JSON envelope (`schema=1`): networks, firewall groups, WLANs, legacy firewall rules, port profiles, DHCP reservations, port forwards, and Zone-Based Firewall policies (operator-created only) with the zones they use, both by name. Secrets are stripped to a sentinel and the envelope is flagged `secrets_stripped: true`. `not_included` names what the envelope does not hold. |
| `restore_config` | write | yes | Compute an action plan from a backup envelope and apply it with rollback on partial failure. It defaults to `dry_run=True`, which returns the plan and writes nothing; `dry_run=False` returns the plan and a one-time token, and nothing is written until `confirm_destructive_action`. References to a recreated network or firewall group are rewritten to its new id. A record the plan cannot place safely is `blocked` and not written (a reference it cannot resolve, a name held more than once); a record the controller will not delete is a `skip`. A type the envelope has no section for is left alone. Zone policies are matched by name plus source and destination zone, created or updated in place through the Integration API (an update puts every field back to the backup's value), and never deleted; controller-managed policies and zones are never written, a name plus zone pair held twice in the backup is `blocked`, and restore does not reorder policies but warns where order may differ. Zone-wide policies (a side matching every network in a zone) are backed up but not restored, because restore cannot prove the zone holds the same networks on the target; recreate them with `create_firewall_policy`. Restored WLANs and networks carrying a stripped secret are recreated with `enabled=False` so the operator resets the secret before they go live. |

## Response envelope shape

Every tool returns a JSON string. Three shapes to expect:

**Success (read or write):**

```json
{ "result": { ... tool-specific payload ... }, "stub_mode": false }
```

**Dry-run preview (write tools with `dry_run=true`):**

```json
{
  "dry_run": true,
  "would_create": { "name": "iot", "vlan": 40, "subnet": "10.0.40.0/24" },
  "preconditions_ok": true,
  "stub_mode": false
}
```

**Composite partial failure (rollback engaged):**

```json
{
  "partial": true,
  "applied": ["vlan_created", "ssid_created"],
  "failed_step": "isolation_rule",
  "failed_reason": "controller returned 400: rule slot exhausted",
  "rolled_back": ["ssid_deleted", "vlan_deleted"],
  "stub_mode": false
}
```

**Structured error (no mutation occurred):**

```json
{ "error": "controller unreachable", "stub_mode": false }
```

The LLM-facing tool descriptions all reference these keys explicitly, which is what drives reliable composite-rollback handling from Claude / Cursor / Cline.

## Common scenarios

**Block a guest device by MAC.**

```jsonc
// Tool: block_client
{ "mac": "aa:bb:cc:dd:ee:ff", "controller": "default", "dry_run": false }
```

**Stand up a fully-isolated IoT network in one call (VLAN + SSID + isolation rule).**

```jsonc
// Tool: create_iot_network
{
  "vlan_id": 40,
  "subnet": "10.0.40.0/24",
  "ssid": "iot",
  "passphrase": "rotate-me",
  "isolate_from_default": true,
  "dry_run": true
}
```

Run it with `dry_run=true` first to inspect the predicted change set. Re-run with `dry_run=false` to apply. If the isolation rule fails, the SSID and VLAN are rolled back automatically.

**Snapshot the controller before a risky change, then audit drift.**

```jsonc
// 1. Take a backup (secrets stripped)
{ "tool": "backup_config", "args": { "controller": "default" } }

// 2. Audit drift against a declared YAML spec
{ "tool": "audit_network_drift", "args": { "spec_yaml": "networks:\n  - name: IoT\n    vlan: 30\n" } }
```

**Pin a homelab service: static lease + LAN-local accept rule + (optional) port forward.**

```jsonc
// Tool: provision_homelab_service
{
  "mac": "11:22:33:44:55:66",
  "ip": "192.168.1.40",
  "hostname": "nas",
  "tcp_ports": [445, 5000],
  "wan_forward": false,
  "dry_run": false
}
```

## Notes

- **Stub mode**: every tool works in stub mode. The in-memory state machine is seeded with one gateway, one AP, one switch, one network, one SSID, one firewall rule, two port profiles, and four clients. Create/update/delete persist for the lifetime of the process and reset on restart.
- **WLAN passphrases**: scrubbed `[REDACTED]` from every response (including stub), and `<scrubbed>` in audit logs.
- **Composite descriptions** include a `Rollback:` contract line describing what gets undone if a sub-step fails.
- **LLM tool selection**: tool descriptions follow a verb-first one-line purpose + `Side effects:` + `Example:` pattern that drives reliable selection from Claude / Cursor / Cline on first touch.
