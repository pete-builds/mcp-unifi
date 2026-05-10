# mcp-unifi

<!-- mcp-name: io.github.pete-builds/unifi -->

[![CI](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml/badge.svg)](https://github.com/pete-builds/mcp-unifi/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/pete-builds/mcp-unifi)](https://github.com/pete-builds/mcp-unifi/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.14-blue.svg)](pyproject.toml)
[![MCP](https://img.shields.io/badge/MCP-Streamable%20HTTP-brightgreen.svg)](https://modelcontextprotocol.io/)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen.svg)](#tests)

An [MCP server](https://modelcontextprotocol.io/) for self-hosted UniFi gateway management. Forty-one tools covering devices, networks/VLANs, WiFi SSIDs (full CRUD), firewall rules (full CRUD), switch port profiles (full CRUD), per-client commands (block / unblock / reconnect / quarantine), per-port state (PoE + enable + profile assignment), static DHCP leases, port forwarding (full CRUD), site health, WAN status, events, alarms, speed tests, DPI top talkers, plus four composite tools with automatic rollback on partial failure: `create_iot_network`, `provision_homelab_service`, `create_guest_network`, and the read-only `audit_open_ports`.

Built on FastMCP with Streamable HTTP transport. Talks to a UCG-Fiber, UDM Pro, or any other UniFi OS gateway via the local API key. No Site Manager / cloud account required.

Every tool returns JSON. Errors come back as a structured `{"error": "...", "stub_mode": bool}` object so the MCP loop never crashes on a gateway hiccup.

## Client compatibility

| MCP client | Transport | Status | Notes |
|---|---|---|---|
| Claude Code | Streamable HTTP | Verified (v0.2.0+, real-mode-ready) | `claude mcp add unifi -t http -s user --url http://<host>:3714/mcp` |
| Claude Desktop | Streamable HTTP | Expected to work; config example below | Hand-edit `claude_desktop_config.json` |
| Gemini CLI (`@google/gemini-cli`) | Streamable HTTP | Verified MCP handshake (v0.36.0) | `gemini mcp add unifi http://<host>:3714/mcp -t http -s user`. Tool list, prompts, and resources discovered successfully. Live tool execution requires a valid Gemini API key / OAuth login. |
| Any custom MCP client | Streamable HTTP | Should work per [MCP spec 2025-03-26+](https://modelcontextprotocol.io/specification) | Endpoint: `http://<host>:3714/mcp` |

## Why

Most UniFi automation today means clicking through the controller UI, writing brittle one-off scripts, or pulling in a heavyweight community SDK. mcp-unifi gives any MCP-aware client (Claude Code, Claude Desktop, custom agents) a small, focused, well-typed surface area for the operations you actually do every week: spin up an IoT VLAN, drop a firewall rule, audit your SSIDs, list adopted devices.

The composite `create_iot_network` tool turns a 15-step UI workflow into a single tool call.

## Quick start

Pull the published image and run it:

```bash
docker run --rm \
  -p 3714:3714 \
  -e STUB_MODE=true \
  ghcr.io/pete-builds/mcp-unifi:0.3.0
```

The server starts in **stub mode** by default, which returns realistic mock data and requires no UniFi hardware. Register it with Claude Code:

```bash
claude mcp add unifi --transport http --scope user --url http://localhost:3714/mcp
```

Then ask Claude Code to "list my UniFi devices" and you should see two stubbed devices come back.

To talk to a real gateway, pass the credentials and flip stub mode off:

```bash
docker run --rm \
  -p 3714:3714 \
  -e STUB_MODE=false \
  -e UNIFI_HOST=192.168.1.1 \
  -e UNIFI_API_KEY=<your-local-api-key> \
  ghcr.io/pete-builds/mcp-unifi:0.3.0
```

Generate the API key under **Settings → Control Plane → Integrations** on the gateway.

## Tool reference

| Tool | Signature | What it does |
|---|---|---|
| `list_devices` | `()` | List adopted gateways, APs, and switches with state, uptime, and per-radio info. |
| `list_networks` | `()` | List all configured networks/VLANs (subnet, DHCP range, VLAN ID). |
| `create_vlan` | `(name, vlan_id, subnet, dhcp_start?, dhcp_stop?, purpose?)` | Create a new VLAN-tagged network. |
| `update_vlan` | `(network_id, updates)` | Patch fields on an existing VLAN. |
| `delete_vlan` | `(network_id)` | Delete a VLAN. |
| `list_wlans` | `()` | List all WiFi SSIDs. |
| `create_wlan` | `(name, passphrase, network_id, security?, wpa_mode?, is_guest?, hide_ssid?, wlan_band?)` | Create a new SSID bound to a specific VLAN. |
| `update_wlan` | `(wlan_id, updates)` | Patch fields on an existing SSID (name, passphrase, hide_ssid, etc.). |
| `delete_wlan` | `(wlan_id)` | Delete a WiFi SSID. |
| `list_firewall_rules` | `()` | List all firewall rules. |
| `create_firewall_rule` | `(name, ruleset, action, rule_index?, protocol?, src_address?, dst_address?, src_networkconf_id?, dst_networkconf_id?, enabled?)` | Create a firewall rule. |
| `delete_firewall_rule` | `(rule_id)` | Delete a firewall rule. |
| `list_port_profiles` | `()` | List switch port profiles (PoE mode, native VLAN, forwarding). |
| `list_clients` | `()` | List currently connected wireless and wired clients (MAC, hostname, IP, signal/satisfaction, AP or switch port, uptime). |
| `update_firewall_rule` | `(rule_id, updates)` | Patch fields on an existing firewall rule. |
| `create_port_profile` | `(name, native_networkconf_id?, forward?, poe_mode?, tagged_networkconf_ids?)` | Create a switch port profile. |
| `update_port_profile` | `(profile_id, updates)` | Patch fields on a port profile. |
| `delete_port_profile` | `(profile_id)` | Delete a port profile. |
| `block_client` | `(mac)` | Block a client by MAC. |
| `unblock_client` | `(mac)` | Unblock a previously-blocked client. |
| `reconnect_client` | `(mac)` | Force a client to reconnect (kick-sta). |
| `restart_device` | `(mac)` | Restart an adopted device (gateway, AP, or switch). |
| `locate_device` | `(mac, on?)` | Toggle the LED locate beacon on a device. |
| `set_port_state` | `(device_mac, port_idx, enable?, poe_mode?, portconf_id?)` | Override settings on one switch port (PoE, enable, profile). Real mode preserves other ports' overrides. |
| `list_dhcp_leases` | `()` | List static DHCP reservations. |
| `create_static_dhcp_lease` | `(mac, ip, network_id, name?, hostname?)` | Reserve a fixed IP for a client. |
| `delete_static_dhcp_lease` | `(lease_id)` | Delete a static reservation. |
| `list_port_forwards` | `()` | List all port-forward (DNAT) rules. |
| `create_port_forward` | `(name, fwd, fwd_port, dst_port, proto?, src?, enabled?, log?)` | Create a port-forward rule. |
| `update_port_forward` | `(forward_id, updates)` | Patch a port-forward rule. |
| `delete_port_forward` | `(forward_id)` | Delete a port-forward rule. |
| `get_site_health` | `()` | Per-subsystem health (wan, lan, wlan, www, vpn). |
| `get_wan_status` | `()` | Just the WAN subsystem record (link, ISP, public IP, throughput, latency). |
| `list_events` | `(limit?)` | Recent controller events. |
| `list_alarms` | `(limit?, archived?)` | Active or archived alarms. |
| `trigger_speedtest` | `()` | Kick off a UniFi WAN speed test. |
| `get_speedtest_results` | `(limit?)` | Recent speed-test results, newest first. |
| `list_top_talkers` | `(limit?)` | Top clients by total bytes (DPI by-station report). |
| `create_iot_network` | `(name, vlan_id, passphrase, main_lan_subnet?, subnet?, isolate?, hide_ssid?)` | One-shot: VLAN + SSID + isolation rule, with rollback on failure. |
| `provision_homelab_service` | `(name, mac, ip, network_id, ports?, wan_expose?)` | Lease + LAN_LOCAL accept + (optional) port forwards. Rolls back on failure. |
| `quarantine_client` | `(mac, reason)` | Block client + structured warning log carrying the reason. |
| `create_guest_network` | `(name, ssid, passphrase, vlan_id, main_lan_subnet?, subnet?, schedule?, hide_ssid?)` | Guest VLAN + guest SSID + isolation rule, with rollback on failure. |
| `audit_open_ports` | `()` | Read-only review of WAN-facing exposure (active port forwards + non-boilerplate WAN accept rules). |

Every tool returns a JSON string. Errors are returned as a structured `{"error": "...", "stub_mode": bool}` object so Claude can render the failure without crashing the MCP loop.

## Stub mode vs real mode

| Mode | When to use | Behavior |
|---|---|---|
| **Stub** (`STUB_MODE=true`, default) | Development, demos, wiring up Claude flows before hardware arrives | In-memory state machine seeded with one gateway, one AP, one network, one SSID, one firewall rule, two port profiles. Create/update/delete persist within the container's lifetime. Resets on restart. |
| **Real** (`STUB_MODE=false`) | Production with a UCG-Fiber/UDM/other UniFi OS gateway | Talks HTTPS to the gateway with your local API key. Requires `UNIFI_HOST` and `UNIFI_API_KEY`. |

Switching modes is a config change, not a code change. The same eleven tools, the same response shapes.

## Configuration

All configuration is read from environment variables (and a `.env` file when present). Config is validated by Pydantic at startup; invalid values fail fast with a helpful message.

| Variable | Type | Default | Required | Notes |
|---|---|---|---|---|
| `STUB_MODE` | bool | `true` | no | When `false`, real-mode credentials are required. |
| `UNIFI_HOST` | string | `""` | only in real mode | Gateway IP or hostname (no scheme). |
| `UNIFI_PORT` | int | `443` | no | HTTPS port for the gateway. |
| `UNIFI_SITE` | string | `default` | no | Controller site identifier. |
| `UNIFI_API_KEY` | string | `""` | only in real mode | Local API key from Settings → Control Plane → Integrations. |
| `UNIFI_VERIFY_SSL` | bool | `false` | no | Set `true` if you have installed a real cert on the gateway. |
| `IOT_SUBNET_TEMPLATE` | string | `10.0.{vlan_id}.0/24` | no | Must contain the literal `{vlan_id}` placeholder. |
| `IOT_DHCP_START_OFFSET` | int (2-254) | `100` | no | First DHCP lease offset within the IoT /24. |
| `IOT_DHCP_STOP_OFFSET` | int (2-254) | `200` | no | Last DHCP lease offset within the IoT /24. |
| `MCP_HOST` | string | `0.0.0.0` | no | Bind address. |
| `MCP_PORT` | int | `3714` | no | Listen port. |
| `LOG_LEVEL` | enum | `INFO` | no | One of `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. |
| `LOG_FORMAT` | enum | `json` | no | `json` for production, `text` for local dev. |

A complete example lives in [`.env.example`](.env.example).

## MCP client setup

### Claude Code

```bash
claude mcp add unifi --transport http --scope user --url http://<host>:3714/mcp
```

### Claude Desktop

Add the following to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unifi": {
      "transport": "streamable-http",
      "url": "http://<host>:3714/mcp"
    }
  }
}
```

### Gemini CLI

[Gemini CLI](https://github.com/google-gemini/gemini-cli) supports MCP servers over Streamable HTTP. The simplest path is the built-in subcommand, which writes the right keys to `settings.json` for you:

```bash
gemini mcp add unifi http://<host>:3714/mcp -t http -s user
gemini mcp list
```

You should see:

```text
Configured MCP servers:

✓ unifi: http://<host>:3714/mcp (http) - Connected
```

If you prefer to hand-edit, drop this into `~/.gemini/settings.json` (user scope) or `<project>/.gemini/settings.json` (project scope). The [canonical Gemini CLI MCP docs](https://www.geminicli.com/docs/tools/mcp-server) use `httpUrl` for Streamable HTTP servers:

```json
{
  "mcpServers": {
    "unifi": {
      "httpUrl": "http://<host>:3714/mcp",
      "timeout": 30000
    }
  }
}
```

The `gemini mcp add` subcommand currently writes a slightly different shape (`"url"` plus `"type": "http"`); both forms are accepted by recent Gemini CLI builds. Stick with whichever matches how you populated the file. Then run `gemini` interactively and use `/mcp` to inspect the connection or list available tools.

**Verified against:** Gemini CLI `0.36.0` on macOS. The MCP handshake (capabilities, tool/prompt/resource discovery, context refresh) completed against `mcp-unifi 0.3.0` running in stub mode. Live tool execution from inside Gemini additionally requires a valid Gemini API key or OAuth login configured in the CLI; this is unrelated to the MCP wiring.

### Generic config

Streamable HTTP at `http://<host>:3714/mcp`. Any MCP client that supports the Streamable HTTP transport ([spec 2025-03-26+](https://modelcontextprotocol.io/specification)) can connect.

## Architecture

```
+---------------------+         Streamable HTTP         +---------------------+
|  MCP Client         |  -------------------------->    |  mcp-unifi          |
|  (Claude Code, etc) |  <--------------------------    |  (FastMCP server)   |
+---------------------+                                 +----------+----------+
                                                                   |
                                                                   |  HTTPS + X-API-Key
                                                                   v
                                                        +----------+----------+
                                                        |  UniFi OS Gateway   |
                                                        |  /proxy/network/... |
                                                        +---------------------+
```

The server is a **thin async proxy**: it translates MCP tool calls into UniFi controller REST calls, shapes the responses, and returns JSON. It does not store state, does not call out to any cloud, and does not authenticate incoming MCP connections (run it on a trusted LAN).

## Security notes

- The `UNIFI_API_KEY` lives only in the container's environment. It is never logged, never echoed back in MCP responses, and never written to disk by this server.
- WLAN passphrases are scrubbed (`[REDACTED]`) on the way out of every tool response, even in stub mode.
- The container runs as **UID 1000**, no shell, no home directory, with a **read-only root filesystem** (`/tmp` is `tmpfs`) and `no-new-privileges`.
- The base image is pinned by digest. Python deps are installed with `pip --require-hashes` from a hash-locked `requirements.lock`.
- The published image is multi-arch (amd64/arm64) with build provenance attestation and SBOM via `docker/build-push-action`.
- The MCP server itself is **not authenticated**. Place it behind a trusted-LAN boundary, a reverse proxy with auth, or a Tailscale ACL.

For vulnerability reports, see [SECURITY.md](SECURITY.md).

## Development

Requires Python 3.13+ and Docker.

```bash
# Clone + install dev deps
git clone https://github.com/pete-builds/mcp-unifi.git
cd mcp-unifi
python -m venv .venv && source .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock
pip install -e . --no-deps

# Run the test suite (224 tests, ~90% coverage)
pytest

# Lint and format
ruff check src tests
ruff format src tests

# Type check (mypy strict)
mypy src/mcp_unifi

# Run the server locally in stub mode
python -m mcp_unifi.server

# Or build the image yourself instead of pulling from GHCR
cp docker-compose.example.yml docker-compose.yml
docker compose up --build
```

### Tests

```text
======================= 224 passed in 9s =======================

Name                              Stmts  Miss  Branch  BrPart  Cover
---------------------------------------------------------------------
src/mcp_unifi/__init__.py             2     0       0       0   100%
src/mcp_unifi/clients/__init__.py     3     0       0       0   100%
src/mcp_unifi/clients/stubs.py      234     2      64       8    97%
src/mcp_unifi/clients/unifi.py      147     5      14       0    96%
src/mcp_unifi/config.py              38     1       8       0    98%
src/mcp_unifi/healthcheck.py         18     1       0       0    94%
src/mcp_unifi/logging_setup.py       33     1      12       2    93%
src/mcp_unifi/models.py               6     0       0       0   100%
src/mcp_unifi/server.py             761   107     242      18    87%
---------------------------------------------------------------------
TOTAL                              1242   117     340      28    90%
```

CI gates on **80% coverage minimum**, ruff lint, ruff format, mypy strict, and a Trivy fs+image scan that fails on any HIGH or CRITICAL finding.

### Updating dependencies

The `requirements.lock` and `requirements-dev.lock` files are hash-pinned. Edit `requirements.in` (or `requirements-dev.in`), then regenerate:

```bash
uv pip compile requirements.in --output-file requirements.lock --generate-hashes --python-version 3.13
uv pip compile requirements-dev.in --output-file requirements-dev.lock --generate-hashes --python-version 3.13
```

Dependabot opens weekly PRs for `requirements.in`-level updates and the Docker base image digest.

## Acknowledgments

UniFi controller endpoint paths were cross-referenced against the [`sirkirby/unifi-mcp`](https://github.com/sirkirby/unifi-mcp) project. That repo was used as research material for the API surface; **no code was copied**. The implementation here is an independent FastMCP + httpx build that follows the proven Forge pattern.

## License

[MIT](LICENSE).

## Contributing

Issues and pull requests welcome. Before opening a PR:

1. Make sure `ruff check`, `ruff format --check`, and `mypy src/mcp_unifi` are clean.
2. Add or update tests, keep coverage at 80% or above.
3. Run `pytest` locally and confirm the suite passes.
4. Update `CHANGELOG.md` under an `[Unreleased]` heading.
