---
draft: false
title: Claude Desktop (.dxt)
description: The Desktop Extension bundle. Built for Linux x86_64 only today; on macOS and Windows use the uvx config.
---

:::caution[Built for Linux x86_64 only today]
On macOS or Windows, use the [Claude Desktop recipe](/mcp-unifi/recipes/claude-desktop/) (`uvx`) instead.

The release workflow builds the `.dxt` on a Linux x86_64 machine with `pip install --target`, so the compiled Python packages inside it (pydantic-core, cryptography, PyYAML and others) are Linux builds. Started on macOS (Apple silicon, Python 3.13), the 0.28.0 bundle stops at its first import with `ImportError: cannot import name 'ArgsKwargs' from 'pydantic_core._pydantic_core'`. Windows has not been tried, but it needs Windows builds of the same packages, which the bundle does not contain. The bundle has not been tried on Linux either. From the next release the bundle's manifest declares Linux as its only platform. One bundle per platform is planned follow-up work.
:::

The Desktop Extension bundle (`.dxt`) installs mcp-unifi into Claude Desktop from one file, configured through a built-in form instead of JSON. The bundle includes the server and its Python dependencies, but not a Python interpreter: its manifest launches `python`, which must be a Python 3.13 (the compiled packages are built for 3.13 exactly).

The bundle uses **stdio transport**: Claude Desktop spawns the server as a subprocess when the conversation starts and tears it down when the conversation ends. There is no long-running server to manage.

## Install

1. Open the [GitHub releases page](https://github.com/pete-builds/mcp-unifi/releases).
2. Download `mcp-unifi-<version>.dxt` from the latest release.
3. Double-click the file. Claude Desktop prompts you to install the extension.
4. Approve the install. The extension appears in **Settings → Extensions** in Claude Desktop.

## Configure

Click the extension's gear icon in **Settings → Extensions** to open the configuration form. Five fields:

| Field | What it sets | Default |
|---|---|---|
| **Stub Mode (sample data)** | `STUB_MODE`. While on, every answer is made-up sample data, even with a host and key filled in. **Turn it off to see your own network.** | On |
| **Read-only** | `MCP_UNIFI_READONLY`. While on, Claude can look but not change anything: every tool that would make a change is hidden and refused. | On |
| **UniFi Host** | `UNIFI_HOST`. IP or hostname (e.g. `192.168.1.1`). Required when Stub Mode is off. | (empty) |
| **UniFi API Key** | `UNIFI_API_KEY`. Local API key from the gateway. The bundle manifest marks this field sensitive. | (empty) |
| **Modules Enabled** | `MCP_UNIFI_MODULES_ENABLED`. Comma-separated. Use `network,protect,access` to enable all three. | `network` |

The Read-only field is new in the bundle after 0.28.0; the 0.28.0 bundle has the other four.

To get the API key, log into the gateway UI, go to **Settings → Control Plane → Integrations**, and click **Create API Key**.

If you fill in the host and key and leave Stub Mode on, the server logs a warning at startup and every answer carries a line saying the data is simulated.

## Verify

Start a new conversation in Claude Desktop and ask: *"list my UniFi devices"*. Claude should select the `list_devices` tool and return a structured list. With Stub Mode on you'll see three made-up devices (a gateway, an access point and a switch). With it off you'll see your adopted gateways, APs, and switches.

If tools don't appear, check **Settings → Extensions** for an enable toggle and confirm the extension is on.

## Why .dxt over manual config

Where the bundle runs, compared to a hand-edited `claude_desktop_config.json` pointing at `uvx`, it:

- Needs no JSON editing. Settings are entered in the extension's configuration form.
- Marks the API key field sensitive in its manifest, so the key is not something you paste into a plaintext config file.
- Sets `MCP_TRANSPORT=stdio` for you, so there is no transport setting to get wrong.

For macOS and Windows today, and whenever you'd rather hand-edit `claude_desktop_config.json`, see the [Claude Desktop recipe](/mcp-unifi/recipes/claude-desktop/).
