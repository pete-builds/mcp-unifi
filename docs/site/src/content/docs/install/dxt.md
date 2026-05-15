---
title: Claude Desktop (.dxt)
description: One-click install for Claude Desktop via the Desktop Extension bundle.
---

The Desktop Extension bundle (`.dxt`) is the easiest way to get mcp-unifi into Claude Desktop. One file, double-click to install, configure through a built-in UI. No JSON editing, no separate runtime to install. The bundle ships the Python runtime and all dependencies inline.

The bundle uses **stdio transport**: Claude Desktop spawns the server as a subprocess when the conversation starts and tears it down when the conversation ends. There is no long-running server to manage.

## Install

1. Open the [GitHub releases page](https://github.com/pete-builds/mcp-unifi/releases).
2. Download `mcp-unifi-<version>.dxt` from the latest release.
3. Double-click the file. macOS / Windows route it to Claude Desktop, which prompts you to install the extension.
4. Approve the install. The extension appears in **Settings → Extensions** in Claude Desktop.

## Configure

Click the extension's gear icon in **Settings → Extensions** to open the configuration UI. Four fields:

| Field | What it sets | Default |
|---|---|---|
| **Stub Mode** | Toggles `STUB_MODE`. On = mock data, no hardware needed. Off = real gateway. | On |
| **UniFi Host** | `UNIFI_HOST`. IP or hostname (e.g. `192.168.1.1`). Required when Stub Mode is off. | (empty) |
| **UniFi API Key** | `UNIFI_API_KEY`. Local API key from the gateway. Stored encrypted by Claude Desktop. | (empty) |
| **Modules Enabled** | `MCP_UNIFI_MODULES_ENABLED`. Comma-separated. Use `network,protect` to enable both. | `network` |

To get the API key, log into the gateway UI, go to **Settings → Control Plane → Integrations**, and click **Create API Key**.

## Verify

Start a new conversation in Claude Desktop and ask: *"list my UniFi devices"*. Claude should select the `list_devices` tool and return a structured list. In stub mode you'll see two mock devices. In real mode you'll see your adopted gateways, APs, and switches.

If tools don't appear, check **Settings → Extensions** for an enable toggle and confirm the extension is on.

## Why .dxt over manual config

The .dxt bundle ships the Python runtime alongside the server code. You don't need `uv`, `pipx`, or `python3` installed on your machine. Compared to a hand-edited `claude_desktop_config.json` pointing at `uvx`, the bundle:

- Survives system-wide Python upgrades.
- Stores the API key encrypted, not in plaintext in a user config file.
- Updates atomically when you install a newer .dxt.

If you'd rather hand-edit `claude_desktop_config.json` (for example, to share one config across machines), see the [Claude Desktop recipe](/mcp-unifi/recipes/claude-desktop/).
