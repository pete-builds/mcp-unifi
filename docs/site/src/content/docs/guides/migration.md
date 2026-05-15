---
title: Migrate from v0.x
description: Upgrade from v0.4.x to v0.5.x without changing your existing config.
---

The v0.5.x line introduces multi-site, dry-run, and the audit log on top of the v0.4.x Network surface. The changes are **additive**: existing v0.4.x configs continue to work unchanged. Read on for the few new env vars that unlock the new behavior when you want it.

## Env vars unchanged

All existing v0.4.x env vars still work:

- `STUB_MODE`
- `UNIFI_HOST`
- `UNIFI_API_KEY`
- `UNIFI_PORT`
- `UNIFI_SITE`
- `UNIFI_VERIFY_SSL`
- `MCP_TRANSPORT`, `MCP_HOST`, `MCP_PORT`
- `LOG_LEVEL`, `LOG_FORMAT`
- `IOT_SUBNET_TEMPLATE`, `IOT_DHCP_START_OFFSET`, `IOT_DHCP_STOP_OFFSET`

Single-controller deployments need **zero config changes** to upgrade. The legacy env vars auto-promote to a one-entry controller list named `default` internally, and every tool's default `controller="default"` parameter routes back to it.

## Tool signatures: only additive

Every tool gained two optional parameters:

- `controller: str = "default"` — names the controller to target. Default routes to your existing single-controller config.
- `dry_run: bool = False` — on destructive tools only. `True` returns the predicted change set without writing.

Existing callers (Claude prompts, scripts, integration tests) that don't pass either parameter behave identically to v0.4.x.

## New: multi-site

To manage more than one controller, write a YAML file and point `MCP_UNIFI_CONTROLLERS_FILE` at it:

```yaml
- name: home
  host: 192.168.1.1
  api_key: <home-api-key>
- name: office
  host: 10.0.0.1
  api_key: <office-api-key>
```

```bash
docker run --rm -p 3714:3714 \
  -e STUB_MODE=false \
  -e MCP_UNIFI_CONTROLLERS_FILE=/etc/mcp-unifi/controllers.yaml \
  -v ./controllers.yaml:/etc/mcp-unifi/controllers.yaml:ro \
  ghcr.io/pete-builds/mcp-unifi:latest
```

When `MCP_UNIFI_CONTROLLERS_FILE` is set, the legacy `UNIFI_HOST` / `UNIFI_API_KEY` env vars are ignored. See the [Multi-Site Setup guide](/mcp-unifi/guides/multi-site/) for the full schema.

## New: enable Protect

The Protect module is opt-in. To load its 12 tools alongside the 46 Network tools, set `MCP_UNIFI_MODULES_ENABLED=network,protect`:

```bash
docker run --rm -p 3714:3714 \
  -e STUB_MODE=false \
  -e UNIFI_HOST=192.168.1.1 \
  -e UNIFI_API_KEY=<your-local-api-key> \
  -e MCP_UNIFI_MODULES_ENABLED=network,protect \
  ghcr.io/pete-builds/mcp-unifi:latest
```

If you only want Protect tools (no Network), set `MCP_UNIFI_MODULES_ENABLED=protect`.

## New: audit log

Audit logging is on by default. The log file lands at `audit.jsonl` in the container's working directory (`/app`).

For a long-running container, you'll want to mount that as a volume so it survives restarts:

```bash
docker run --rm -p 3714:3714 \
  -e UNIFI_HOST=192.168.1.1 \
  -e UNIFI_API_KEY=<your-local-api-key> \
  -e MCP_UNIFI_AUDIT_PATH=/var/log/mcp-unifi/audit.jsonl \
  -v ./logs:/var/log/mcp-unifi \
  ghcr.io/pete-builds/mcp-unifi:latest
```

Or set `MCP_UNIFI_AUDIT_SINK=stdout` to route the log to the container's stdout for collection by Docker / Kubernetes log drivers. See the [Dry-Run & Audit Log guide](/mcp-unifi/guides/dry-run-audit/) for the field schema and replay tooling.

## Tool count

| Version | Tool count |
|---|---|
| v0.4.x (Network only) | 41 |
| v0.5.0-rc.1 (Network + multi-site + dry-run + audit) | 43 |
| v0.5.0-rc.2 (added `audit_network_drift`, `backup_config`, `restore_config`) | 46 |
| v0.5.0-rc.2 + Protect enabled | 58 |

No tools were removed. The added tools are read-only (`audit_network_drift`, `backup_config`) or honor `dry_run` (`restore_config`).

## What to verify after upgrade

1. **Tool list**: `tools/list` returns the expected count for your module config.
2. **Existing tool calls**: a representative call from your prior usage (e.g. `list_devices`, `create_vlan`) returns the same shape.
3. **Audit log**: confirm the log file is being written and rotated by your log infra.
4. **Multi-site (if used)**: `list_devices(controller="home")` and `list_devices(controller="office")` return disjoint device lists.
