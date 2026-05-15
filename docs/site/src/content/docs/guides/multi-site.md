---
title: Multi-Site Setup
description: Configure mcp-unifi to manage multiple UniFi controllers from one server.
---

mcp-unifi can manage more than one UniFi controller from a single server instance. Every tool accepts an optional `controller: str = "default"` parameter; that parameter names one of the controllers in your config and routes the call to it.

This is the architectural commitment that's painful to retrofit. It's the only feature that genuinely differentiates mcp-unifi from the competing UniFi MCP servers, and it's also the one most homelab operators end up wanting once they have more than one site (home + parents', home + office, etc).

## Config sources, in priority order

The server picks controller config from the first source that resolves:

1. `MCP_UNIFI_CONTROLLERS_FILE` — YAML file with a list of named controllers.
2. Legacy single-controller env vars (`UNIFI_HOST`, `UNIFI_API_KEY`, `UNIFI_PORT`, `UNIFI_SITE`, `UNIFI_VERIFY_SSL`) auto-promoted to `controllers=[ControllerConfig(name="default", ...)]`.
3. `STUB_MODE=true` with no controller config: synthesizes a single `default` stub controller.

Real mode with no controller config from any source is a hard validation error.

## YAML config

Create a file (anywhere readable to the server process) and point `MCP_UNIFI_CONTROLLERS_FILE` at it:

```yaml
# /etc/mcp-unifi/controllers.yaml
- name: home
  host: 192.168.1.1
  api_key: <home-api-key>
  port: 443
  site: default
  verify_ssl: false

- name: office
  host: 10.0.0.1
  api_key: <office-api-key>
  port: 443
  site: default
  verify_ssl: false
```

A dict-with-key form is also accepted:

```yaml
controllers:
  - name: home
    host: 192.168.1.1
    api_key: <home-api-key>
  - name: office
    host: 10.0.0.1
    api_key: <office-api-key>
```

## Per-controller fields

| Field | Required | Default | Notes |
|---|---|---|---|
| `name` | yes | — | Stable identifier used by tools. No duplicates allowed. |
| `host` | yes | — | UniFi gateway IP or hostname (no scheme). |
| `api_key` | yes | — | Local API key from the gateway. Wrapped in `SecretStr` internally; never logged. |
| `port` | no | `443` | HTTPS port for the gateway. |
| `site` | no | `default` | UniFi controller site name. Most setups have one site called `default`. |
| `verify_ssl` | no | `false` | Set `true` if the gateway has a real TLS certificate. |

## Use it from a tool call

Every tool accepts `controller="<name>"`:

```
list_devices(controller="home")
list_devices(controller="office")
create_vlan(name="iot", vlan_id=50, subnet="10.50.0.0/24", controller="home", dry_run=True)
```

If `controller` is omitted, the call routes to the controller named `default`. If no `default` controller exists in your config, every call must name a controller explicitly.

## Docker example

```bash
# Mount the YAML and point MCP_UNIFI_CONTROLLERS_FILE at it
docker run --rm -p 3714:3714 \
  -e STUB_MODE=false \
  -e MCP_UNIFI_CONTROLLERS_FILE=/etc/mcp-unifi/controllers.yaml \
  -v ./controllers.yaml:/etc/mcp-unifi/controllers.yaml:ro \
  ghcr.io/pete-builds/mcp-unifi:latest
```

## Stub mode with two controllers

Stub mode honors the YAML config too. This is useful for testing multi-site flows before pointing at real hardware:

```yaml
- name: home
  host: stub-home
  api_key: stub
- name: office
  host: stub-office
  api_key: stub
```

```bash
docker run --rm -p 3714:3714 \
  -e STUB_MODE=true \
  -e MCP_UNIFI_CONTROLLERS_FILE=/etc/mcp-unifi/controllers.yaml \
  -v ./controllers.yaml:/etc/mcp-unifi/controllers.yaml:ro \
  ghcr.io/pete-builds/mcp-unifi:latest
```

Each controller gets its own in-memory state. Creating a VLAN on `home` does not affect `office`.

## Helm

In `values.yaml`, mount an `existingSecret` containing the API keys and a `ConfigMap` containing the YAML. The chart's `values.yaml.unifi.*` block is the **simple single-controller** path; for multi-site, prefer the existingSecret + ConfigMap pattern and mount the YAML into the pod. See the chart's `templates/` directory for the volume hooks.
