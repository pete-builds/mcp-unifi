---
draft: false
title: Access Tools
description: Full reference for the 18 Access module tools.
---

The Access module covers UniFi Access doors, credentials, visitor passes, badge-scan events, and hub / reader hardware. v0.10 ships **read-only** tools: door unlocks, credential issuance, and visitor-pass creation are deferred to a future v0.11+ that introduces session-token auth alongside the API key (see the v0.10 spec doc for the Option A vs. Option B decision).

## Enabling

The Access module is **opt-in**. Set:

```bash
MCP_UNIFI_MODULES_ENABLED=network,protect,access
```

If you only want Access (no Network, no Protect):

```bash
MCP_UNIFI_MODULES_ENABLED=access
```

When the env var is unset, only Network is loaded.

## Conventions

Every tool accepts an optional `controller: str = "default"` parameter. The v0.10 surface has no `dry_run` parameter because every tool is read-only.

The Access tool surface is intentionally narrow: no door unlocks, no credential issuance, no visitor pass creation, no policy updates, no device reboots. v0.10 covers forensics, audits, summaries, and visibility, which is the bulk of the LLM use cases for Access. Write tools land in a later release gated by a separate explicit decision.

## Read-only

### Doors

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_doors` | read | — | List every door bonded to the Access controller. Includes `id`, `name`, `location`, `hub_id`, `locked`, `online`, `door_position_status`, `lock_status`, and `last_activity` (epoch ms). |
| `get_door` | read | — | Fetch one door's full record by ID. |
| `list_door_groups` | read | — | List every door group on the controller. Door groups bundle doors for access-policy assignment. |

### Access policies

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_access_policies` | read | — | List every access policy. Each ties a schedule, one or more door groups, and a set of users / credential types. |
| `get_access_policy` | read | — | Fetch one access policy's full record by ID. |

### Credentials

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_credentials` | read | — | List every credential enrolled in the controller. Includes `type` (`nfc`, `pin`, `mobile`), `label`, `user_id`, `status`, `issued_at`, `expires_at`. |
| `get_credential` | read | — | Fetch one credential's full record. Type-specific fields (`card_id`, `pin_length`, `device_label`) come back as well. |
| `audit_expiring_credentials` | read | — | Return credentials expiring inside the next `days_ahead` days (default 30). Optional `credential_type` narrows to one of `nfc`, `pin`, `mobile`. Each entry includes a computed `days_until_expiry`. |

### Visitors

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_visitors` | read | — | List every visitor pass (active and past). |
| `get_visitor` | read | — | Fetch one visitor pass's full record by ID. |

### Events

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_access_events` | read | — | List badge-scan / door events with filters. `result` filters to `granted` or `denied`; empty returns both. `door_id` narrows to one door. |
| `get_recent_access_events` | read | — | Last `limit` events across every door over the last 24h. Convenience wrapper for triage. |
| `summarize_access_activity` | read | — | Aggregate badge events by door, user, and outcome over the last `hours_back` hours. Returns `total`, `granted`, `denied`, plus `by_door` and `by_user` rollups. |
| `list_failed_access_attempts` | read | — | Return only `result == "denied"` events within the window. Each entry includes a `reason` (`expired`, `off-hours`, `unknown_pin`, etc.). |

### Devices

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `list_access_devices` | read | — | List hubs, readers, relays, and intercoms. Includes `type` (`hub` or `reader`), `model`, `firmware_version`, `online`. |
| `get_access_device` | read | — | Fetch one Access device's full record by ID. |

### System

| Tool | Type | dry_run | Description |
|---|---|---|---|
| `get_access_system_info` | read | — | Controller version, release channel, license tier (`doors_used`, `doors_max`, `users_used`, `users_max`), uptime. |
| `list_access_users` | read | — | List every user enrolled in the Access system. |

## Stub mode

In stub mode, the Access backend exposes:

- 2 doors (`Main Entrance`, `Server Room`) and 1 door group containing both
- 1 access policy (`Business Hours — All Users`)
- 3 credentials, one of each type: NFC card (5-day expiry), PIN (90-day expiry), mobile credential (no expiry)
- 1 active visitor pass (`Dave Delivery`)
- 50 synthetic events spread across the last 24 hours, mixed `granted` / `denied`
- 3 users (`Alice Admin`, `Bob Builder`, `Carol Contractor`)
- 1 hub and 2 readers (one per door)

Every cross-reference is wired correctly: `users[].credential_ids` lists the credentials that belong to each user, readers point at their parent door and hub, etc.

## Notes on enums

- **`credential_type`** (for `audit_expiring_credentials`): one of `"nfc"`, `"pin"`, `"mobile"`, or empty for all.
- **`result`** (for `list_access_events`): one of `"granted"`, `"denied"`, or empty for both.

## Real-mode prerequisites

The Access tools require a UniFi Access controller reachable on its own host (often the same gateway as Network, sometimes a standalone hub) with a local **Access API key**. Set, in addition to the Network connection variables:

```bash
UNIFI_ACCESS_HOST=192.168.1.20
UNIFI_ACCESS_PORT=12445
UNIFI_ACCESS_API_KEY=<access-key>
```

Or, when using a `MCP_UNIFI_CONTROLLERS_FILE`, set the per-controller `access_host`, `access_port`, and `access_api_key` fields. The Access API key only authorises GETs; the dual-auth path required for writes is not implemented in v0.10.

If `MCP_UNIFI_MODULES_ENABLED` includes `access` but no controller has Access credentials configured, calls to Access tools return a clean `AccessNotAvailableError` envelope rather than failing deep inside the HTTP client.
