---
draft: false
title: Access Setup
description: Configure mcp-unifi to talk to a UniFi Access hub.
---

The Access module covers UniFi Access doors, credentials, visitor passes, badge-scan events, and hub / reader hardware. It currently ships **read-only** tools only. Door unlocks, credential issuance, and visitor-pass creation require session-token auth alongside the API key and are deferred.

## Why read-only

UniFi Access has a wrinkle that Network and Protect do not: mutations require a local username / password session, not the local API key. The API key only authorises GETs against the read-only endpoints.

The Access module sticks with API-key reads so the project's API-key-first security posture stays intact. No admin password ever sits in env. The read-only tools cover forensics, audits, summaries, and visibility, which is the bulk of LLM use cases for Access.

When write tools land in a later release, they will require setting `UNIFI_ACCESS_USERNAME` and `UNIFI_ACCESS_PASSWORD` alongside the API key. The bearer token still gates the MCP transport unchanged.

## Enabling the module

The Access module is opt-in. Add it to `MCP_UNIFI_MODULES_ENABLED`:

```bash
# All three modules
MCP_UNIFI_MODULES_ENABLED=network,protect,access

# Access only
MCP_UNIFI_MODULES_ENABLED=access
```

If the env var is unset, only Network loads.

## Configuring credentials

### Single-controller (env vars)

If you have one UniFi controller and the Access hub is co-located or reachable from the same env, set:

```bash
UNIFI_HOST=192.168.1.1
UNIFI_API_KEY=<network-api-key>

UNIFI_ACCESS_HOST=192.168.1.20        # often the same as UNIFI_HOST
UNIFI_ACCESS_PORT=12445               # default; the direct Access app port
UNIFI_ACCESS_API_KEY=<access-api-key>
```

The Access API key is **separate** from the Network API key. Generate it under the Access controller's developer settings, not Settings → Control Plane → Integrations on the gateway.

### Multi-controller (YAML)

When using `MCP_UNIFI_CONTROLLERS_FILE`, set the per-controller `access_*` fields:

```yaml
- name: home
  host: 192.168.1.1
  api_key: <home-network-key>
  port: 443
  access_host: 192.168.1.20
  access_port: 12445
  access_api_key: <home-access-key>

- name: office
  host: 10.0.0.1
  api_key: <office-network-key>
  # No access_* fields — office controller has no Access hub.
```

Controllers without `access_host` and `access_api_key` simply do not register an Access backend. Calls to Access tools that target those controllers return an `UnknownControllerError` envelope.

## Stub mode

Set `STUB_MODE=true` (the default) and the module wires an in-memory state with 2 doors, 1 door group, 1 access policy, 3 credentials (NFC / PIN / mobile), 1 visitor pass, 50 synthetic events, 3 users, 1 hub, 2 readers. No hardware required.

This is the v0.10 development substrate: real-mode integration tests are respx-mocked because Pete does not have Access hardware. A community tester (or future hardware acquisition) is what validates real mode in a v0.10.x point release.

## Verifying it's wired

After starting the server with `MCP_UNIFI_MODULES_ENABLED` including `access`, call any read tool. From an MCP client (Claude Desktop, n8n, etc):

```text
list_doors(controller="default")
```

Expected: a JSON list of doors. If you see `Access backends are not configured on this registry`, you set the module name but did not provide `UNIFI_ACCESS_HOST` + `UNIFI_ACCESS_API_KEY`. Add them and restart.

## Common patterns

**Audit credentials about to expire:**

```text
audit_expiring_credentials(days_ahead=30)
```

Returns every credential whose `expires_at` falls inside the next 30 days, sorted by closest expiry first, with a computed `days_until_expiry` so the LLM does not have to do the math.

**Find recent failed entries on the server room door:**

```text
list_failed_access_attempts(door_id="<door_id>", hours_back=24)
```

Each entry includes the `reason` (`expired`, `off-hours`, `unknown_pin`, etc.) so the LLM can summarise the cause distribution.

**Who badged in where over the last day:**

```text
summarize_access_activity(hours_back=24)
```

Returns `total`, `granted`, `denied`, plus `by_door` and `by_user` rollups sorted by activity volume.
