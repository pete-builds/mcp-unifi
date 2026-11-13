---
draft: false
title: uvx / pipx
description: Run mcp-unifi straight from the GitHub repo with no install footprint.
---

`uvx` (from [uv](https://docs.astral.sh/uv/)) is the fastest way to try mcp-unifi on a machine that already has Python tooling. With `MCP_TRANSPORT=stdio` set, the server runs over **stdio**, the transport Claude Desktop and Claude Code's stdio path spawn. Nothing is installed system-wide; `uvx` caches the package in its own directory.

## One-off run

The server's default transport is Streamable HTTP, which refuses to start without a bearer token. For a stdio run, set `MCP_TRANSPORT=stdio`:

```bash
MCP_TRANSPORT=stdio uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

That command resolves the repo, builds a venv, installs the package, and starts the server on stdio. A stdio server waits for an MCP client on stdin, so in a terminal it sits silent until you press `Ctrl+C`. `STUB_MODE` defaults to `true`, so with no other settings it serves mock data.

To pin a release, append `@<tag>` to the git URL, where `<tag>` is a release tag from the [releases page](https://github.com/pete-builds/mcp-unifi/releases):

```bash
MCP_TRANSPORT=stdio uvx --from git+https://github.com/pete-builds/mcp-unifi@<tag> mcp-unifi
```

## Wire into Claude Code

Add it as a stdio MCP server in Claude Code (user scope):

```bash
claude mcp add --transport stdio --scope user unifi \
  --env MCP_TRANSPORT=stdio \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi mcp-unifi
```

`STUB_MODE` defaults to `true`, so that registration serves made-up sample data with no hardware. For your own network, pass the gateway env vars as well. This form is read-only and pinned to a release; drop `MCP_UNIFI_READONLY=true` when you want Claude to make changes:

```bash
claude mcp add --transport stdio --scope user unifi \
  --env MCP_TRANSPORT=stdio \
  --env STUB_MODE=false \
  --env MCP_UNIFI_READONLY=true \
  --env UNIFI_HOST=192.168.1.1 \
  --env UNIFI_API_KEY=<your-local-api-key> \
  -- uvx --from git+https://github.com/pete-builds/mcp-unifi@v0.28.0 mcp-unifi
```

Leaving `STUB_MODE` out while setting a host and key still serves the simulator's data. From 0.29.0 the server then logs a warning at startup and every answer says the data is simulated; v0.28.0 says nothing.

**Tested where:** the `uvx` route was tested on macOS (Apple silicon) in stub mode. Not yet tested on Windows.

Verify with `claude mcp list`. The `unifi` entry should report `Connected`.

## pipx

`pipx` works too if you don't have `uv` installed:

```bash
pipx install git+https://github.com/pete-builds/mcp-unifi
MCP_TRANSPORT=stdio mcp-unifi
```

`pipx` installs the package globally for your user; remove it later with `pipx uninstall mcp-unifi`.

## Notes

- The `mcp-unifi` console script does not pick a transport for you. Unless `MCP_TRANSPORT=stdio` is set, it starts the Streamable HTTP transport and exits with `HTTP transport requires MCP_UNIFI_AUTH_TOKENS` when no token is configured. Every stdio command on this page therefore sets it. If you want Streamable HTTP, use the [Docker install](/mcp-unifi/install/docker/) instead.
- Multi-controller config via `MCP_UNIFI_CONTROLLERS_FILE` works the same as in Docker; point the env var at a YAML file the uvx process can read.
- The audit log path defaults to `audit.jsonl` in the CWD of wherever `uvx` ran. Set `MCP_UNIFI_AUDIT_PATH=/path/to/audit.jsonl` to override.
