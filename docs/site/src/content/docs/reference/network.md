---
draft: false
title: Network Tools
description: Full reference for the 46 Network module tools.
---

The Network module is loaded by default (`MCP_UNIFI_MODULES_ENABLED=network`). It exposes 46 tools covering devices, networks/VLANs, WLANs, firewall rules, switch port profiles, per-client commands, static DHCP leases, port forwards, observability, plus composites with rollback and config drift / backup utilities.

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

## DHCP

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_dhcp_leases` | read | — | List static DHCP reservations. |
| `create_static_dhcp_lease` | write | yes | Reserve a fixed IP for a new MAC. |
| `update_static_dhcp_lease` | write | yes | Convert/update an existing client to a fixed IP (use when MAC is already known). |
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
| `list_events` | read | — | Recent controller events. |
| `list_alarms` | read | — | Active or archived alarms. |
| `trigger_speedtest` | write | — | Kick off a UniFi WAN speed test. (Read-side-effects only; no config mutation.) |
| `get_speedtest_results` | read | — | Recent speed-test results, newest first. |
| `list_top_talkers` | read | — | Top clients by total bytes (DPI by-station report). |

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
| `audit_network_drift` | read | — | Compare current controller state to a declared YAML spec; returns structured diff. |
| `backup_config` | read | — | Snapshot controller state into a versioned JSON envelope (`schema=1`). WLAN passphrases stripped to a sentinel; envelope flagged `secrets_stripped: true`. |
| `restore_config` | write | yes | Compute an action plan from a backup envelope and apply it with rollback on partial failure. Restored WLANs from a secrets-stripped envelope are recreated with `enabled=False` so the operator resets passphrases before they go live. |

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
{ "tool": "audit_network_drift", "args": { "spec_path": "./network-spec.yml" } }
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
